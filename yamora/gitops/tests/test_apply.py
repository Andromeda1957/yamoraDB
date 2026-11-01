"""Guarded GitOps apply through real Git objects and the immutable native daemon."""

import copy
import json
import os
import re
import select
import subprocess
import sys
import time
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import patch

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.gitops import ApplyUncertainError
from yamora.gitops import Limits
from yamora.gitops import PlanError
from yamora.gitops import PreparedDB
from yamora.gitops import apply_db
from yamora.gitops import apply_prepared_db
from yamora.gitops import build_plan
from yamora.gitops import capture_export
from yamora.gitops import prepare_db
from yamora.gitops.model import canonical
from yamora.gitops.model import digest
from yamora.gitops.tests.test_gitops import MAP
from yamora.gitops.tests.test_gitops import GitFixture


def rehash(plan):
    plan["plan_id"] = digest(canonical({k: v for k, v in plan.items() if k != "plan_id"}))


class NativeApplyTests(GitFixture):
    def setUp(self):
        super().setUp()
        binary = os.environ.get("YAMORA_TEST_BINARY")
        if not binary:
            self.fail("YAMORA_TEST_BINARY must name the immutable native daemon")
        self.data = self.root / "native"
        self.data.mkdir()
        for name in ("read", "write"):
            path = self.root / name
            path.write_text(name[0] * 32)
            path.chmod(0o600)
        result = subprocess.run(
            [binary, "--data-dir", str(self.data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.process = subprocess.Popen(
            [
                binary,
                "--data-dir",
                str(self.data),
                "--port",
                "0",
                "--auth-token-file",
                str(self.root / "read"),
                "--write-auth-token-file",
                str(self.root / "write"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop)
        self.assertTrue(select.select([self.process.stdout], [], [], 10)[0])
        line = self.process.stdout.readline()
        match = re.search(rb"127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line)
        self.client = YamoraClient(
            port=int(match[1]),
            timeout=5,
            auth_token_file=self.root / "read",
            write_auth_token_file=self.root / "write",
        )

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        _, error = self.process.communicate(timeout=15)
        self.assertEqual(self.process.returncode, 0, error)
        self.assertNotIn(b"Sanitizer", error)

    def make_plan(self, base_docs, git_docs, db_docs=None):
        for key, value in (base_docs if db_docs is None else db_docs).items():
            self.client.put("people", key, value)
        base = self.commit(base_docs)
        selected = self.commit(git_docs)
        return build_plan(self.repo, base, selected, capture_export(self.client, MAP), MAP)

    def test_atomic_create_update_delete_and_exact_bytes(self):
        old = b"# original\r\nname: Alice # comment\r\n"
        new = "# new\r\nname: 'Alïce' # exact\r\n".encode()
        plan = self.make_plan({"update": old, "delete": old}, {"update": new, "create": new})
        before_git = self.git("status", "--porcelain")
        result = apply_db(
            self.client, self.repo, plan, expected_plan_id=plan["plan_id"], request_id="1" * 32
        )
        self.assertEqual(result["receipt"]["status"], "committed")
        self.assertEqual(result["receipt"]["operations"], 3)
        self.assertEqual(self.client.documents("people"), ["create", "update"])
        for name in ("create", "update"):
            self.assertEqual(self.client.get("people", name), new)
        self.assertEqual(self.git("status", "--porcelain"), before_git)

    def apply(self, plan, **kwargs):
        return apply_db(
            self.client,
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            request_id="2" * 32,
            **kwargs,
        )

    def prepared(self, plan, **kwargs):
        return prepare_db(
            self.repo, plan, expected_plan_id=plan["plan_id"], request_id="2" * 32, **kwargs
        )

    def unchanged(self, before):
        self.assertEqual(capture_export(self.client, MAP).to_dict(), before.to_dict())

    def test_stale_live_revision_collection_metadata_and_incomplete_export(self):
        plan = self.make_plan({}, {"new": b"value: 1\n"})
        # Empty collection metadata remains after deleting its last document.
        self.client.put("people", "race", b"value: 2\n")
        self.client.delete("people", "race")
        before = capture_export(self.client, MAP)
        self.assertEqual(before.collections, ("people",))
        with self.assertRaises(PlanError):
            self.apply(plan)
        self.unchanged(before)
        # Falsely calling this present empty collection absent is detectable
        # even with the right global revision and a self-consistent new plan ID.
        exported = before.to_dict()
        exported["collections"] = []
        base = self.commit({})
        current = self.commit({"new": b"value: 1\n"})
        bad = build_plan(self.repo, base, current, exported, MAP)
        with self.assertRaises(PlanError):
            self.apply(bad)
        self.unchanged(before)
        self.client.put("people", "omitted", b"x: 1\n")
        before = capture_export(self.client, MAP)
        exported = before.to_dict()
        exported["documents"] = []
        bad = build_plan(self.repo, base, current, exported, MAP)
        with self.assertRaises(PlanError):
            self.apply(bad)
        self.unchanged(before)

    def test_conflicts_and_rehashed_decision_blob_summary_and_unknown_field_tampering(self):
        plan = self.make_plan({"one": b"x: 1\n"}, {"one": b"x: 2\n"})
        before = capture_export(self.client, MAP)
        variants = []
        for path, value in (
            (("entries", 0, "target"), "git"),
            (("summary", "update"), 0),
            (("entries", 0, "git", "bytes"), 999),
            (("entries", 0, "git", "sha256"), "0" * 64),
            (("entries", 0, "git", "source_b64"), "eDogMwo="),
            (("entries", 0, "preconditions", "git", "blob_oid"), "0" * 40),
            (("preconditions", "git", "baseline_tree"), "0" * 40),
            (("entries", 0, "path"), "../outside.yaml"),
            (("entries", 0, "preconditions", "db", "create_only"), True),
            (("entries", 0, "db", "present"), 1),
            (("summary", "converged"), False),
            (("preconditions", "mappings", 0, "prefix"), "--upload-pack"),
            (("preconditions", "db", "revision"), "f" * 16),
            (("preconditions", "db", "export_sha256"), "0" * 64),
            (("entries", 0, "unknown"), True),
            (("preconditions", "db", "unknown"), True),
            (("unknown",), True),
        ):
            bad = copy.deepcopy(plan)
            target = bad
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            rehash(bad)
            variants.append(bad)
        for bad in variants:
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                self.apply(bad)
        self.unchanged(before)
        conflict = self.make_plan({"one": b"x: 1\n"}, {"one": b"x: 2\n"}, {"one": b"x: 3\n"})
        before = capture_export(self.client, MAP)
        with self.assertRaises(PlanError):
            self.apply(conflict)
        self.unchanged(before)

    def test_expected_identity_request_identity_and_write_credential_are_mandatory(self):
        plan = self.make_plan({}, {"new": b"x: 1\n"})
        for identity in (None, "0" * 64, plan["plan_id"].upper()):
            with self.subTest(identity=identity), self.assertRaises(PlanError):
                apply_db(
                    self.client, self.repo, plan, expected_plan_id=identity, request_id="1" * 32
                )
            with self.subTest(prepare_identity=identity), self.assertRaises(PlanError):
                prepare_db(self.repo, plan, expected_plan_id=identity, request_id="1" * 32)
        for request_id in (None, "0" * 32, "A" * 32, "x", False):
            with self.subTest(request_id=request_id), self.assertRaises(PlanError):
                prepare_db(self.repo, plan, expected_plan_id=plan["plan_id"], request_id=request_id)
        self.client._write_token = None
        with self.assertRaises(PlanError):
            self.apply(plan)
        self.assertEqual(self.client.collections(), [])

    def test_empty_db_targets_have_no_receipt_or_writes_and_git_targets_stay_pending(self):
        source = b"# database side\r\nx: 2\r\n"
        plan = self.make_plan({"one": b"x: 1\n"}, {"one": b"x: 1\n"}, {"one": source})
        before = capture_export(self.client, MAP)
        with patch.object(self.client, "_request", wraps=self.client._request) as requests:
            result = self.apply(plan)
        self.assertEqual(result["status"], "no_db_operations")
        self.assertIsNone(result["receipt"])
        self.assertEqual(result["pending_git"], ["data/people/one.yaml"])
        self.assertEqual(requests.call_count, 0)
        self.assertEqual((self.repo / "data/people/one.yaml").read_bytes(), b"x: 1\n")
        self.unchanged(before)

    def test_unchanged_apply_is_local_after_database_advance(self):
        plan = self.make_plan({"one": b"x: 1\n"}, {"one": b"x: 1\n"})
        self.client.put("people", "one", b"x: 2\n")
        with patch.object(self.client, "_request", wraps=self.client._request) as requests:
            result = self.apply(plan)
        self.assertEqual(requests.call_count, 0)
        self.assertEqual(result["status"], "no_db_operations")
        self.assertIsNone(result["receipt"])
        self.assertEqual(self.client.get("people", "one"), b"x: 2\n")

    def test_empty_apply_is_local_when_database_unavailable(self):
        plan = self.make_plan({}, {})
        with patch.object(
            self.client, "_request", side_effect=YamlDBClientError("offline", transport=True)
        ) as requests:
            result = self.apply(plan)
        self.assertEqual(requests.call_count, 0)
        self.assertEqual(result["status"], "no_db_operations")
        self.assertIsNone(result["receipt"])
        self.assertEqual(result["pending_git"], [])

    def test_empty_apply_still_validates_local_identity_types_credentials_and_deadline(self):
        plan = self.make_plan({}, {})
        frozen = self.prepared(plan)
        arguments = {
            "client": self.client,
            "prepared": frozen,
            "expected_plan_id": frozen.plan_id,
        }
        with patch.object(self.client, "_request") as requests:
            for changed in (
                {"expected_plan_id": "0" * 64},
                {"prepared": None},
                {"client": None},
                {"recover": 1},
                {"_deadline": time.monotonic() - 1},
            ):
                with self.subTest(changed=changed), self.assertRaises(PlanError):
                    apply_prepared_db(**(arguments | changed))
            self.client._write_token = None
            with self.assertRaises(PlanError):
                apply_prepared_db(**arguments)
        self.assertEqual(requests.call_count, 0)

    def test_invalid_yaml_empty_and_non_utf8_never_publish_partial_batch(self):
        for invalid in (b"x: [unclosed\n", b"", b"x: \xff\n"):
            with self.subTest(invalid=invalid):
                plan = self.make_plan({}, {"a-valid": b"x: 1\n", "z-invalid": invalid})
                before = capture_export(self.client, MAP)
                with self.assertRaises((PlanError, YamlDBClientError)):
                    self.apply(plan)
                self.unchanged(before)
                # Also exercise the native boundary, bypassing Python validators.
                value = {
                    "revision": before.revision,
                    "operations": [
                        {
                            "collection": "people",
                            "document": "a-valid",
                            "put": "x: 1\n",
                            "create_only": True,
                        },
                        {
                            "collection": "people",
                            "document": "z-invalid",
                            "put": invalid.decode("latin1"),
                            "create_only": True,
                        },
                    ],
                }
                raw = YamoraClient._encode_json(value)
                if b"\xff" in invalid:
                    raw = raw.replace("ÿ".encode(), b"\xff")
                with self.assertRaises(YamlDBClientError):
                    self.client._request(
                        "/v1/transactions",
                        method="POST",
                        body=raw,
                        content_type="application/json",
                        accept="application/json",
                        write=True,
                    )
                self.unchanged(before)

    def test_native_revision_etag_and_absence_guards_are_atomic(self):
        self.client.put("people", "existing", b"x: 1\n")
        before = capture_export(self.client, MAP)
        valid = {
            "collection": "people",
            "document": "a-valid",
            "put": b"x: 2\n",
            "create_only": True,
        }
        cases = [
            ([valid], "f" * 16),
            (
                [
                    valid,
                    {
                        "collection": "people",
                        "document": "existing",
                        "put": b"x: 3\n",
                        "etag": "f" * 16,
                    },
                ],
                before.revision,
            ),
            (
                [
                    valid,
                    {
                        "collection": "people",
                        "document": "existing",
                        "delete": True,
                        "etag": "f" * 16,
                    },
                ],
                before.revision,
            ),
            (
                [
                    valid,
                    {
                        "collection": "people",
                        "document": "existing",
                        "put": b"x: 3\n",
                        "create_only": True,
                    },
                ],
                before.revision,
            ),
        ]
        for operations, revision in cases:
            with self.subTest(operations=operations), self.assertRaises(YamlDBClientError):
                self.client.transaction(operations, revision=revision)
            self.unchanged(before)

    def test_race_after_preflight_is_rejected_by_same_transaction_revision(self):
        plan = self.make_plan({"one": b"x: 1\n"}, {"one": b"x: 2\n", "new": b"x: 3\n"})
        original = self.client._request
        dispatched = []

        def race(path, **options):
            if options.get("write"):
                dispatched.append(json.loads(options["body"]))
                original(
                    "/v1/collections/unrelated/documents/race",
                    method="PUT",
                    body=b"x: 9\n",
                    content_type="application/yaml",
                    accept="application/json",
                    write=True,
                    expected=(201,),
                )
            return original(path, **options)

        with (
            patch.object(self.client, "_request", side_effect=race),
            self.assertRaises(YamlDBClientError),
        ):
            self.apply(plan)
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(dispatched[0]["revision"], plan["preconditions"]["db"]["revision"])
        self.assertEqual(self.client.documents("people"), ["one"])
        self.assertEqual(self.client.get("people", "one"), b"x: 1\n")

    def test_128_commits_and_129_rejects_before_dispatch_without_chunking(self):
        docs = {f"doc-{i:03d}": b"x: 1\n" for i in range(129)}
        plan = self.make_plan({}, docs)
        with patch.object(self.client, "_request", wraps=self.client._request) as requests:
            with self.assertRaises(PlanError):
                self.apply(plan)
        self.assertEqual(requests.call_count, 0)
        plan = self.make_plan({}, dict(list(docs.items())[:128]))
        with patch.object(self.client, "_request", wraps=self.client._request) as requests:
            result = self.apply(plan)
        self.assertEqual(result["receipt"]["operations"], 128)
        self.assertEqual(sum(bool(call.kwargs.get("write")) for call in requests.call_args_list), 1)
        self.assertEqual(len(self.client.documents("people")), 128)

    def test_frozen_input_envelope_and_explicit_standalone_uncertainty_no_replay(self):
        plan = self.make_plan({}, {"new": b"# exact\r\nx: 1\r\n"})
        frozen = self.prepared(plan)
        restored = PreparedDB.from_dict(
            self.repo, frozen.to_dict(), expected_plan_id=plan["plan_id"]
        )
        self.assertEqual(restored, frozen)
        with self.assertRaises(FrozenInstanceError):
            frozen.body = b"changed"
        plan["entries"][0]["git"]["source_b64"] = "changed"
        original = self.client._request
        writes = []

        def lost(path, **options):
            result = original(path, **options)
            if options.get("write"):
                writes.append((options["body"], options["headers"]))
                raise YamlDBClientError("lost", transport=True)
            return result

        with (
            patch.object(self.client, "_request", side_effect=lost),
            self.assertRaises(ApplyUncertainError) as raised,
        ):
            apply_prepared_db(self.client, frozen, expected_plan_id=frozen.plan_id)
        error = raised.exception
        self.assertIs(error.prepared, frozen)
        self.assertEqual(
            (error.operation, error.plan_id, error.request_id),
            (frozen.body, frozen.plan_id, frozen.request_id),
        )
        self.assertEqual(writes, [(frozen.body, {"X-Yamora-Request-Id": frozen.request_id})])
        self.assertEqual(self.client.get("people", "new"), b"# exact\r\nx: 1\r\n")
        with self.assertRaises(PlanError):
            apply_prepared_db(self.client, frozen, expected_plan_id=frozen.plan_id, recover=True)
        with self.assertRaises(PlanError):
            apply_prepared_db(self.client, frozen, expected_plan_id=frozen.plan_id)

    def test_receipt_validation_cancellation_and_decode_deadline_preserve_operation(self):
        plan = self.make_plan({}, {"new": b"x: 1\n"})
        frozen = self.prepared(plan)
        revision = "1" * 16
        good = {"status": "committed", "operations": 1, "revision": revision}
        receipts = [
            b"{",
            b"[]",
            b'{"status":"committed","status":"committed","operations":1,"revision":"1111111111111111"}',
        ]
        receipts += [
            canonical({**good, **change})
            for change in (
                {"status": "stored"},
                {"operations": True},
                {"operations": 2},
                {"operations": 1.0},
                {"revision": "2" * 16},
                {"unknown": True},
            )
        ]
        original = self.client._request
        for receipt in receipts + [KeyboardInterrupt(), TimeoutError()]:
            writes = []

            def respond(path, *, receipt=receipt, writes=writes, **options):
                if not options.get("write"):
                    return original(path, **options)
                writes.append(options["body"])
                if isinstance(receipt, BaseException):
                    raise receipt
                return receipt, "application/json", {"x-yamldb-revision": revision}

            with (
                self.subTest(receipt=receipt),
                patch.object(self.client, "_request", side_effect=respond),
                self.assertRaises(ApplyUncertainError) as raised,
            ):
                apply_prepared_db(self.client, frozen, expected_plan_id=frozen.plan_id)
            self.assertEqual(raised.exception.operation, frozen.body)
            self.assertEqual(writes, [frozen.body])

    def test_total_deadline_covers_git_export_dispatch_and_decode(self):
        plan = self.make_plan({}, {"new": b"x: 1\n"})
        frozen = self.prepared(plan)
        original = self.client._request
        budgets = []
        now = [time.monotonic()]
        clock = SimpleNamespace(monotonic=lambda: now[0])

        def slow(path, **options):
            budgets.append(options["_timeout"])
            now[0] += 2
            return original(path, **options)

        with (
            patch("yamora.gitops.apply.time", clock),
            patch("yamora.gitops.export.time", clock),
            patch("yamora.gitops.validation.time", clock),
            patch.object(self.client, "_request", side_effect=slow),
            self.assertRaises((PlanError, YamlDBClientError)),
        ):
            self.apply(plan, limits=Limits(deadline=5))
        self.assertEqual(budgets, [5, 3, 1])
        self.assertEqual(self.client.collections(), [])
        now[0] = time.monotonic()

        def late(path, **options):
            result = original(path, **options)
            if options.get("write"):
                now[0] += 6
            return result

        with (
            patch("yamora.gitops.apply.time", clock),
            patch("yamora.gitops.validation.time", clock),
            patch.object(self.client, "_request", side_effect=late),
            self.assertRaises(ApplyUncertainError),
        ):
            apply_prepared_db(
                self.client, frozen, expected_plan_id=frozen.plan_id, limits=Limits(deadline=5)
            )
        self.assertEqual(self.client.get("people", "new"), b"x: 1\n")

    def test_prepare_and_apply_cli_preserve_exact_source_and_leave_git_untouched(self):
        plan = self.make_plan({}, {"new": b"# cli\r\nx: 1\r\n"})
        filename = self.root / "plan.json"
        filename.write_bytes(canonical(plan))
        common = ["--repo", str(self.repo), "--expected-plan-id", plan["plan_id"]]
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamora.gitops",
                "prepare-db",
                *common,
                "--plan-file",
                str(filename),
                "--request-id",
                "3" * 32,
            ],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        filename.write_bytes(result.stdout)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamora.gitops",
                "apply-db",
                *common,
                "--prepared-file",
                str(filename),
                "--port",
                str(self.client.port),
                "--auth-token-file",
                str(self.root / "read"),
                "--write-auth-token-file",
                str(self.root / "write"),
            ],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["receipt"]["operations"], 1)
        self.assertEqual(self.client.get("people", "new"), b"# cli\r\nx: 1\r\n")
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_actual_encoded_request_byte_ceiling_rejects_before_any_database_io(self):
        # Four valid YAML sources below the document/combined source limits,
        # whose JSON escaping alone exceeds the actual 64 MiB wire ceiling.
        source = b"x: 1\n#" + b"\\" * (8 * 1024 * 1024 - 7) + b"\n"
        plan = self.make_plan({}, {f"doc-{i}": source for i in range(4)})
        with patch.object(self.client, "_request", wraps=self.client._request) as requests:
            with self.assertRaisesRegex(PlanError, "encoded database transaction"):
                self.apply(plan)
        self.assertEqual(requests.call_count, 0)
        self.assertEqual(self.client.collections(), [])

    def test_envelope_rejects_changed_bytes_and_json_nonfinite_duplicate_fields(self):
        plan = self.make_plan({}, {"one": b"x: 1\n"})
        frozen = self.prepared(plan)
        value = frozen.to_dict()
        value["operation_b64"] = "e30="
        with self.assertRaises(PlanError):
            PreparedDB.from_dict(self.repo, value, expected_plan_id=plan["plan_id"])
        for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(payload=payload), self.assertRaises(PlanError):
                prepare_db(
                    self.repo, payload, expected_plan_id=plan["plan_id"], request_id="2" * 32
                )

    def test_mutation_during_live_preflight_cannot_change_frozen_operation(self):
        plan = self.make_plan({}, {"one": b"x: 1\r\n"})
        expected = self.prepared(plan).body
        original = self.client._request
        writes = []

        def mutate(path, **options):
            plan.clear()
            if options.get("write"):
                writes.append(options["body"])
            return original(path, **options)

        identity = plan["plan_id"]
        with patch.object(self.client, "_request", side_effect=mutate):
            result = apply_db(
                self.client, self.repo, plan, expected_plan_id=identity, request_id="2" * 32
            )
        self.assertEqual(result["receipt"]["operations"], 1)
        self.assertEqual(writes, [expected])
        self.assertEqual(self.client.get("people", "one"), b"x: 1\r\n")

    def test_receipt_decoding_cannot_reset_total_deadline(self):
        plan = self.make_plan({}, {"new": b"x: 1\n"})
        frozen = self.prepared(plan)
        from yamora.gitops.model import strict_json

        now = [time.monotonic()]
        clock = SimpleNamespace(monotonic=lambda: now[0])

        def slow(payload):
            result = strict_json(payload)
            if result.get("status") == "committed":
                now[0] += 6
            return result

        with (
            patch("yamora.gitops.apply.time", clock),
            patch("yamora.gitops.validation.time", clock),
            patch("yamora.gitops.apply.strict_json", side_effect=slow),
            self.assertRaises(ApplyUncertainError) as raised,
        ):
            apply_prepared_db(
                self.client, frozen, expected_plan_id=frozen.plan_id, limits=Limits(deadline=5)
            )
        self.assertIs(raised.exception.prepared, frozen)
        self.assertEqual(self.client.get("people", "new"), b"x: 1\n")

    def test_mixed_targets_apply_only_db_and_report_git_pending(self):
        old, new, from_db = b"x: 1\r\n", b"# git\r\nx: 2\r\n", b"# db\r\nx: 3\r\n"
        plan = self.make_plan(
            {"from-db": old, "from-git": old},
            {"from-db": old, "from-git": new},
            {"from-db": from_db, "from-git": old},
        )
        result = self.apply(plan)
        self.assertEqual(result["receipt"]["operations"], 1)
        self.assertEqual(result["pending_git"], ["data/people/from-db.yaml"])
        self.assertEqual(self.client.get("people", "from-db"), from_db)
        self.assertEqual(self.client.get("people", "from-git"), new)
        self.assertEqual((self.repo / "data/people/from-db.yaml").read_bytes(), old)
