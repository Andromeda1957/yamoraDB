"""Run public document contracts against the paged production engine."""

import subprocess

from yamora.tests import test_document_api as api


class DiskApiTests(api.DocumentApiTests):
    def change_page(self, after=None, *, limit=100, port=None):
        import json

        target = "/v1/changes" if after is None else f"/v1/changes?after={after}&limit={limit}"
        status, headers, body = self.request(target, method="GET", port=port)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def test_change_feed_rejects_foreign_future_malformed_and_unauthenticated_tokens(self):
        current = self.change_page()
        token = current["next_after"]
        for bad, expected in (("bad", 400), (token[:-16] + "f" * 16, 409)):
            with self.subTest(token=bad):
                self.assertEqual(
                    self.request("/v1/changes?after=" + bad, method="GET")[0], expected
                )
        foreign = self.root / "foreign"
        foreign.mkdir()
        port = self.start(foreign)
        self.assertEqual(
            self.request("/v1/changes?after=" + token, method="GET", port=port)[0], 409
        )
        self.assertEqual(
            self.request("/v1/changes", method="GET", headers={"Authorization": ""})[0], 401
        )
        for options in (
            "limit=0",
            "limit=101",
            "limit=-1",
            "limit=x",
            "limit=2&limit=2",
            "after=",
            "unknown=1",
        ):
            self.assertEqual(self.request("/v1/changes?" + options, method="GET")[0], 400)

    def test_change_feed_pages_restart_and_rejected_writes(self):
        start = self.change_page()["next_after"]
        path = "/v1/collections/people/documents/alice"
        self.assertEqual(
            self.request(
                path,
                {"$inc": {"rating": 1}},
                method="PATCH",
                write=True,
                headers={"If-Match": '"0000000000000000"'},
            )[0],
            412,
        )
        self.assertEqual(self.change_page(start)["transactions"], [])
        for _ in range(5):
            self.assertEqual(
                self.request(path, {"$inc": {"rating": 1}}, method="PATCH", write=True)[0], 200
            )
        seen = []
        token = start
        while True:
            page = self.change_page(token, limit=2)
            seen.extend(page["transactions"])
            token = page["next_after"]
            if not page["has_more"]:
                break
        self.assertEqual(len(seen), 5)
        self.assertEqual(len({item["token"] for item in seen}), 5)
        for previous, current in zip(seen, seen[1:], strict=False):
            self.assertEqual(previous["revision"], current["previous_revision"])
        process = self.processes[0]
        process.terminate()
        process.wait(timeout=10)
        self.port = self.start(self.data)
        resumed = self.change_page(start)
        self.assertEqual(resumed["transactions"], seen)
        self.assertEqual(resumed["next_after"], token)

    def test_change_feed_reports_catalog_rebuild_as_resnapshot(self):
        from yamora.client import YamlDBClient

        token = self.change_page()["next_after"]
        client = YamlDBClient(
            port=self.port, auth_token_file=self.read, write_auth_token_file=self.write, timeout=20
        )
        client.create_index("people", "rating", ["rating"])
        transactions = self.change_page(token)["transactions"]
        self.assertEqual(len(transactions), 1)
        self.assertTrue(transactions[0]["resnapshot_required"])
        self.assertEqual(transactions[0]["operations"], [])
        self.assertEqual(transactions[0]["revision"], client.snapshot_revision())

    def test_change_feed_bounds_bulk_capture_by_identities_and_source_bytes(self):
        for name, count, width in (("many-keys", 300, 1), ("many-bytes", 80, 240000)):
            with self.subTest(name=name):
                source = self.root / name
                (source / "items").mkdir(parents=True)
                for number in range(count):
                    (source / "items" / f"d-{number:03}.yaml").write_text(
                        "text: " + "x" * width + "\n"
                    )
                port = self.start(source)
                checkpoint = self.change_page(port=port)
                history = self.change_page(checkpoint["oldest_after"], port=port)
                self.assertEqual(len(history["transactions"]), 1)
                self.assertTrue(history["transactions"][0]["resnapshot_required"])
                self.assertEqual(history["transactions"][0]["operations"], [])
                self.assertEqual(history["transactions"][0]["revision"], checkpoint["revision"])

    def test_change_feed_response_byte_limit_preserves_whole_commits(self):
        from yamora.client import YamlDBClient

        client = YamlDBClient(port=self.port, auth_token_file=self.read, timeout=20)
        token = client.changes()["next_after"]
        source = "text: |\n  " + '"' * 500000 + "\n"
        for batch in range(9):
            operations = [
                {"collection": "large", "document": f"b-{batch}-{number}", "put": source}
                for number in range(8)
            ]
            status, _, body = self.request(
                "/v1/transactions", {"operations": operations}, write=True
            )
            self.assertEqual(status, 200, body)
        page = client.changes(token)
        self.assertTrue(page["has_more"])
        self.assertLess(len(page["transactions"]), 9)
        frames = list(client.iter_changes(token))
        self.assertEqual(len(frames), 9)
        for number, frame in enumerate(frames):
            puts = [op for op in frame["operations"] if "document" in op]
            self.assertEqual(len(puts), 8)
            self.assertTrue(all(op["put"] == source for op in puts))
            self.assertTrue(all(op["document"].startswith(f"b-{number}-") for op in puts))

    def test_change_feed_preserves_atomic_transaction_and_exact_source(self):
        import json

        status, _, body = self.request("/v1/changes", method="GET")
        self.assertEqual(status, 200, body)
        checkpoint = json.loads(body)
        self.assertEqual(checkpoint["transactions"], [])
        token = checkpoint["next_after"]
        source = "# exact comment\r\nname: Carol\r\nrating: 2700 # keep\r\n"
        status, headers, body = self.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "people", "document": "carol", "put": source},
                    {"collection": "people", "document": "alice", "delete": True},
                ]
            },
            write=True,
        )
        self.assertEqual(status, 200, body)
        committed = json.loads(body)["revision"]
        status, feed_headers, body = self.request("/v1/changes?after=" + token, method="GET")
        self.assertEqual(status, 200, body)
        feed = json.loads(body)
        self.assertEqual(len(feed["transactions"]), 1)
        transaction = feed["transactions"][0]
        self.assertEqual(transaction["revision"], committed)
        self.assertEqual(transaction["previous_revision"], checkpoint["revision"])
        self.assertEqual(feed_headers["X-YamlDB-Revision"], committed)
        operations = {op["document"]: op for op in transaction["operations"]}
        self.assertEqual(operations["carol"]["put"], source)
        self.assertIs(operations["alice"]["delete"], True)
        self.assertEqual(transaction["token"], feed["next_after"])
        self.assertFalse(feed["has_more"])
        status, _, body = self.request("/v1/changes?after=" + feed["next_after"], method="GET")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["transactions"], [])

    def start(self, data, *extra):
        if not (data / ".yamora-disk").exists():
            target = data.with_name(data.name + "-disk")
            if (target / ".yamora-disk").exists():
                return super().start(target, "--cache-bytes", "32768", *extra)
            target.mkdir()
            result = subprocess.run(
                [
                    str(api.BINARY),
                    "--data-dir",
                    str(target),
                    "--init-disk",
                    "--import-yaml",
                    str(data),
                    "--cache-bytes",
                    "32768",
                    "--validate-only",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = target
        return super().start(data, "--cache-bytes", "32768", *extra)

    def test_patch_keeps_unmodified_source_and_rejects_stale_write(self):
        path = "/v1/collections/people/documents/alice"
        _, headers, _ = self.request(path, method="GET")
        status, _, body = self.request(
            path,
            {"$inc": {"rating": 10}},
            method="PATCH",
            write=True,
            headers={"If-Match": headers["ETag"]},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            self.request(path, method="GET")[2], self.original.replace(b"2400", b"2410")
        )
        self.assertEqual((self.data / "people/alice.yaml").read_bytes(), self.original)
        self.assertEqual(
            self.request(
                path,
                {"$inc": {"rating": 10}},
                method="PATCH",
                write=True,
                headers={"If-Match": headers["ETag"]},
            )[0],
            412,
        )

    def test_transaction_envelope_supports_near_limit_documents(self):
        payload = "value: " + "x" * 200000 + "\n"
        status, _, body = self.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "large", "document": name, "put": payload}
                    for name in ("one", "two")
                ]
            },
            write=True,
        )
        self.assertEqual(status, 200, body)
        for name in ("one", "two"):
            self.assertEqual(
                self.request(f"/v1/collections/large/documents/{name}", method="GET")[2],
                payload.encode(),
            )
        self.assertFalse((self.data / "large").exists())

    def test_replication_can_replace_disjoint_maximum_collection_sets(self):
        from yamora.client import YamlDBClient

        source_data, target_data = self.root / "maximum-source", self.root / "maximum-replica"
        for number in range(256):
            (source_data / f"a-{number:03}").mkdir(parents=True)
            (target_data / f"z-{number:03}").mkdir(parents=True)
        source = YamlDBClient(port=self.start(source_data), auth_token_file=self.read, timeout=20)
        target = YamlDBClient(
            port=self.start(target_data, "--replica"),
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=20,
        )
        self.assertEqual(target.replicate_from(source)["revision"], source.snapshot_revision())
        self.assertEqual(target.collections(), source.collections())
        self.assertEqual(len(list(target_data.glob("z-*"))), 256)

    def test_parallel_writers_recompute_patches_and_pin_commit_receipts(self):
        import concurrent.futures
        import json

        from yamora.client import YamlDBClient

        path = "/v1/collections/people/documents/alice"
        start = self.change_page()["next_after"]

        def increment(_):
            status, headers, body = self.request(
                path, {"$inc": {"rating": 1}}, method="PATCH", write=True
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(json.loads(body)["revision"], headers["X-YamlDB-Revision"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(increment, range(160)))
        result = json.loads(self.request("/v1/query/people", {"filter": {"name": "Alice"}})[2])
        self.assertEqual(result["documents"][0]["value"]["rating"], 2560)
        client = YamlDBClient(port=self.port, auth_token_file=self.read, timeout=20)
        frames = list(client.iter_changes(start))
        self.assertEqual(len(frames), 160)
        self.assertEqual(len({frame["token"] for frame in frames}), 160)
        for number, frame in enumerate(frames, 2401):
            self.assertFalse(frame["resnapshot_required"])
            self.assertEqual(len(frame["operations"]), 1)
            self.assertEqual(
                frame["operations"][0]["put"].encode(),
                self.original.replace(b"2400", str(number).encode()),
            )
        self.assertEqual(client.changes(frames[-1]["token"])["transactions"], [])

    def test_filter_updates_serialize_and_publish_resolved_writes(self):
        import concurrent.futures
        import json

        start = self.change_page()["next_after"]
        operation = {
            "collection": "people",
            "filter": {"name": "Alice", "rating": {"$gte": 2400}},
            "update": {"$inc": {"rating": 1}},
        }

        def increment(_):
            status, _, body = self.request(
                "/v1/transactions", {"operations": [operation]}, write=True
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(json.loads(body)["updates"][0]["modified"], 1)

        # Concurrent filter updates retry against newer snapshots; no increment is lost.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(increment, range(40)))
        frames = self.change_page(start)["transactions"]
        self.assertEqual(len(frames), 40)
        # The feed and replicas receive the resolved exact source, never the filter.
        for number, frame in enumerate(frames, 2401):
            self.assertEqual(
                [(op["collection"], op["document"], op["put"]) for op in frame["operations"]],
                [
                    (
                        "people",
                        "alice",
                        self.original.replace(b"2400", str(number).encode()).decode(),
                    )
                ],
            )
        last = frames[-1]["token"]
        unchanged = {**operation, "filter": {"name": "Nobody"}}
        status, _, body = self.request("/v1/transactions", {"operations": [unchanged]}, write=True)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["status"], "unchanged")
        self.assertEqual(self.change_page(last)["transactions"], [])

    def test_query_pages_exceed_legacy_response_cap_through_public_client(self):
        from yamora.client import YamlDBClient

        operations = [
            {"collection": "large", "document": f"d{i:03}", "put": "text: " + ("x" * 20000) + "\n"}
            for i in range(20)
        ]
        self.assertEqual(
            self.request("/v1/transactions", {"operations": operations}, write=True)[0], 200
        )
        client = YamlDBClient(port=self.port, auth_token_file=self.read, timeout=20)
        result = client.query("large", {"limit": 20, "include_count": False})
        self.assertEqual(len(result["documents"]), 20)
        self.assertIsNone(result["matched"])
        self.assertGreater(len(str(result)), 256 * 1024)

    def test_native_dump_restores_exact_sources_and_rebuilds_indexes(self):
        from yamora.backup import dump
        from yamora.backup import restore_dump
        from yamora.backup import verify_dump
        from yamora.client import YamlDBClient

        source = YamlDBClient(
            port=self.port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=30,
        )
        source.create_index("people", "rating", ["rating"], unique=True)
        archive = self.root / "native.dump"
        summary = dump(source, archive)
        self.assertEqual(verify_dump(archive), summary)
        restored = self.root / "restored-native"
        self.assertEqual(restore_dump(archive, restored, binary=api.BINARY), summary)
        self.assertEqual((restored / "people/alice.yaml").read_bytes(), self.original)
        target = YamlDBClient(port=self.start(restored), auth_token_file=self.read, timeout=30)
        self.assertEqual(target.snapshot_revision(), source.snapshot_revision())
        self.assertEqual(target.indexes(), source.indexes())
        page = target.query("people", {"filter": {"rating": 2400}, "explain": True})
        self.assertEqual([document["id"] for document in page["documents"]], ["alice"])
        self.assertEqual(page["explain"]["index"], "rating")

    def test_large_requested_page_shrinks_by_bytes_without_losing_rows(self):
        from yamora.client import YamlDBClient

        client = YamlDBClient(
            port=self.port, auth_token_file=self.read, write_auth_token_file=self.write, timeout=30
        )
        payload = "text: " + ("x" * 200000) + "\n"
        for base in range(0, 350, 7):
            client.transaction(
                [
                    {"collection": "large", "document": f"d{i:04}", "put": payload}
                    for i in range(base, base + 7)
                ]
            )
        revision = client.snapshot_revision()
        after = None
        names = []
        while True:
            spec = {"limit": 1000}
            if after is not None:
                spec["after"] = after
            result = client.query("large", spec, revision=revision)
            self.assertTrue(result["documents"])
            self.assertLess(len(result["documents"]), 1000)
            names.extend(item["id"] for item in result["documents"])
            after = result["next_after"]
            if after is None:
                break
        self.assertEqual(names, [f"d{i:04}" for i in range(350)])

    def test_compaction_preserves_current_root_and_source_history(self):
        import json

        path = "/v1/collections/people/documents/alice"
        for _ in range(20):
            self.assertEqual(
                self.request(path, {"$inc": {"rating": 1}}, method="PATCH", write=True)[0], 200
            )
        _, headers, expected = self.request(path, method="GET")
        process = self.processes[0]
        process.terminate()
        process.wait(timeout=10)
        source = self.data.with_name(self.data.name + "-disk")
        original = (source / ".yamora-disk").read_bytes()
        target = self.root / "compacted"
        target.mkdir()
        result = subprocess.run(
            [
                str(api.BINARY),
                "--data-dir",
                str(source),
                "--compact-to",
                str(target),
                "--cache-bytes",
                "32768",
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["revision"], headers["X-YamlDB-Revision"])
        self.assertEqual((source / ".yamora-disk").read_bytes(), original)
        self.assertLess((target / ".yamora-disk").stat().st_size, len(original))
        port = self.start(target)
        self.assertEqual(self.request(path, method="GET", port=port)[2], expected)

    def test_cross_backend_replication_uses_destination_revision_scheme(self):
        from yamora.client import YamlDBClient

        legacy_data = self.root / "legacy-replica"
        legacy_data.mkdir()
        legacy_port = api.DocumentApiTests.start(self, legacy_data, "--replica")
        source = YamlDBClient(port=self.port, auth_token_file=self.read, timeout=20)
        legacy = YamlDBClient(
            port=legacy_port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=20,
        )
        result = legacy.replicate_from(source)
        self.assertEqual(result["revision"], legacy.snapshot_revision())
        self.assertEqual(legacy.get("people", "alice"), source.get("people", "alice"))
        self.assertNotEqual(legacy.snapshot_revision(), source.snapshot_revision())
        replica = self.root / "disk-replica"
        replica.mkdir()
        disk = YamlDBClient(
            port=self.start(replica, "--replica"),
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=20,
        )
        self.assertEqual(disk.replicate_from(legacy)["revision"], source.snapshot_revision())
        self.assertEqual(disk.get("people", "alice"), self.original)

    def test_failed_import_keeps_sentinel_and_rejects_startup(self):
        source = self.root / "invalid-source"
        (source / "items").mkdir(parents=True)
        owner = source / "items/one.yaml"
        owner.write_text("key: &unsafe [alias]\n")
        target = self.root / "failed"
        target.mkdir()
        result = subprocess.run(
            [
                str(api.BINARY),
                "--data-dir",
                str(target),
                "--init-disk",
                "--import-yaml",
                str(source),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((target / ".yamora-initializing").is_file())
        checked = subprocess.run(
            [str(api.BINARY), "--data-dir", str(target), "--validate-only"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("incomplete", checked.stderr)
        self.assertEqual(owner.read_text(), "key: &unsafe [alias]\n")
