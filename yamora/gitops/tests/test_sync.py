"""Synthetic repositories and exact-byte state-machine fault/restart acceptance."""

import base64
import json
import unittest
from unittest.mock import patch

from yamora.client import YamlDBClient
from yamora.gitops.git_apply import GitPublishUncertainError
from yamora.gitops.git_artifacts import GitArtifacts
from yamora.gitops.git_writer import _Child
from yamora.gitops.model import Export
from yamora.gitops.model import Mapping
from yamora.gitops.model import PlanError
from yamora.gitops.model import canonical
from yamora.gitops.model import digest
from yamora.gitops.model import etag
from yamora.gitops.planner import build_plan
from yamora.gitops.sync import PreparedSync
from yamora.gitops.sync import SyncUncertainError
from yamora.gitops.sync import observe_sync
from yamora.gitops.sync import plan_from_checkpoint
from yamora.gitops.sync import prepare_sync
from yamora.gitops.sync import run_sync
from yamora.gitops.sync import stage_sync
from yamora.gitops.tests.test_git_signing import META
from yamora.gitops.tests.test_git_signing import TARGET
from yamora.gitops.tests.test_git_signing import SyntheticGit

MAP = [Mapping("people", "data/people")]
OWNERSHIP = [
    {"collection": "people", "prefix": "data/people", "upstream": "both", "downstream": "both"}
]
DATABASE = "d" * 32


class ModelDB(YamlDBClient):
    """State-machine fixture only. Native integration has separate real API tests."""

    def __init__(self, documents):
        self.documents = dict(documents)
        self.calls = []
        self._write_token = "synthetic"
        self.collections_present = bool(documents)
        self.lost_ack = False

    def export(self):
        return Export.from_dict(
            {
                "format": "yamora-gitops-export-v1",
                "revision": digest(
                    canonical(sorted((k, v.hex()) for k, v in self.documents.items()))
                )[:16],
                "revision_scheme": "xor-fnv-v2",
                "scope": ["people"],
                "collections": ["people"] if self.collections_present else [],
                "documents": [
                    {
                        "collection": "people",
                        "document": key,
                        "etag": etag(source),
                        "source_b64": base64.b64encode(source).decode(),
                    }
                    for key, source in sorted(self.documents.items())
                ],
            }
        )

    def _request(self, path, **kwargs):
        self.calls.append((path, kwargs))
        request = json.loads(kwargs["body"])
        if request["revision"] != self.export().revision:
            raise AssertionError("synthetic fixture rejected stale request")
        for operation in request["operations"]:
            key = operation["document"]
            if "put" in operation:
                self.documents[key] = operation["put"].encode()
                self.collections_present = True
            else:
                self.documents.pop(key)
        if self.lost_ack:
            raise OSError("synthetic lost DB acknowledgment")
        receipt = {
            "status": "committed",
            "operations": len(request["operations"]),
            "revision": self.export().revision,
        }
        return canonical(receipt), "application/json", {"x-yamldb-revision": receipt["revision"]}


class SyncTests(SyntheticGit, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.key, self.public = self.make_key()
        self.store = GitArtifacts(self.artifacts)
        self.addCleanup(self.store.close)
        for target in ("yamora.gitops.sync.capture_export", "yamora.gitops.apply.capture_export"):
            patcher = patch(target, side_effect=lambda client, *a, **k: client.export())
            patcher.start()
            self.addCleanup(patcher.stop)

    def setup_sync(self, baseline, selected, db, ownership=None):
        self.client = ModelDB(db)
        self.base = self.commit(baseline)
        self.current = self.commit(selected)
        self.git("update-ref", TARGET, self.current)
        self.plan = build_plan(self.repo, self.base, self.current, self.client.export(), MAP)
        self.prepared = prepare_sync(
            self.repo,
            self.plan,
            expected_plan_id=self.plan["plan_id"],
            database_id=DATABASE,
            operation_id="a" * 32,
            ownership=ownership or OWNERSHIP,
            target_ref=TARGET,
            expected_old_commit=self.current,
            commit_metadata=META,
            signer_policy=self.public,
        )
        return self.prepared

    def stage(self):
        self.staged = stage_sync(
            self.repo,
            self.prepared,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            signer_config=self.key,
        )
        return self.staged

    def execute(self, **kwargs):
        return run_sync(
            self.client,
            self.repo,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            database_id=DATABASE,
            **kwargs,
        )

    def tip(self):
        return self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode()

    def test_mixed_exact_sources_and_repeat_restart_have_one_db_one_git_effect(self):
        old = {"git": b"x: 1\n", "db": b"x: 2\n", "delete": b"x: 3\n"}
        selected = {"git": b"# authored\r\nx: 'new'\r\n", "db": old["db"], "add": b"x: 4"}
        db = {**old, "db": b"# DB comment\nx: db\n"}
        self.setup_sync(old, selected, db)
        frozen = self.prepared.to_dict()
        self.assertEqual(
            PreparedSync.from_dict(
                self.repo, frozen, expected_sync_id=self.prepared.sync_id
            ).to_dict(),
            frozen,
        )
        index = (self.repo / ".git/index").read_bytes()
        self.stage()
        self.assertEqual(self.client.calls, [])
        self.assertEqual(self.tip(), self.current)
        checkpoint = self.execute()
        self.assertEqual(self.client.documents, {**selected, "db": db["db"]})
        self.assertEqual(len(self.client.calls), 1, "SINGLE_DB_EFFECT")
        self.assertEqual(self.tip(), checkpoint["baseline_commit"])
        self.assertEqual(
            self.git("rev-parse", self.tip() + "^").stdout.strip().decode(), self.current
        )
        for name, source in self.client.documents.items():
            self.assertEqual(
                self.git("show", self.tip() + ":data/people/" + name + ".yaml").stdout, source
            )
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip().decode(), self.current)
        self.assertEqual((self.repo / ".git/index").read_bytes(), index)
        self.assertEqual(self.execute(), checkpoint)
        self.assertEqual(len(self.client.calls), 1, "RESTART_MUST_NOT_REPEAT_DB")
        next_plan = plan_from_checkpoint(
            self.repo,
            self.tip(),
            self.client.export(),
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            expected_checkpoint_id=checkpoint["checkpoint_id"],
        )
        self.assertEqual(next_plan["summary"]["unchanged"], 3)
        self.assertTrue(all(e["target"] == "none" for e in next_plan["entries"]))

    def test_all_three_conflicts_fail_before_artifacts_or_effects(self):
        for base, selected, db in (
            ({}, {"x": b"x: 1"}, {"x": b"x: 2"}),
            ({"x": b"x: 0"}, {}, {"x": b"x: 2"}),
            ({"x": b"x: 0\n"}, {"x": b"x: 0\r\n"}, {"x": b"# comment\nx: 0\n"}),
        ):
            with self.subTest(base=base), self.assertRaisesRegex(PlanError, "conflict"):
                self.setup_sync(base, selected, db)
            self.assertEqual(self.client.calls, [])
            self.assertEqual(list(self.artifacts.iterdir()), [])

    def test_both_one_way_ownership_policies_reject_excluded_authored_side(self):
        for upstream, downstream, selected, db in (
            ("git", "db", {"x": b"x: 0"}, {"x": b"x: db"}),
            ("db", "git", {"x": b"x: git"}, {"x": b"x: 0"}),
        ):
            ownership = [{**OWNERSHIP[0], "upstream": upstream, "downstream": downstream}]
            with self.subTest(upstream=upstream), self.assertRaisesRegex(PlanError, "ownership"):
                self.setup_sync({"x": b"x: 0"}, selected, db, ownership)
            self.assertEqual(self.client.calls, [])

    def test_identity_tampering_and_mapping_omission_fail_closed(self):
        self.setup_sync({}, {"x": b"x: 1"}, {})
        for field, changed in (
            ("database_id", "e" * 32),
            ("ownership", []),
            ("operation_id", "b" * 32),
        ):
            value = self.prepared.to_dict()
            value[field] = changed
            with self.subTest(field=field), self.assertRaises(PlanError):
                PreparedSync.from_dict(self.repo, value, expected_sync_id=self.prepared.sync_id)
        value = self.prepared.to_dict()
        value["prepared_db"]["request_id"] = "f" * 32
        value["sync_id"] = digest(canonical({k: v for k, v in value.items() if k != "sync_id"}))
        with self.assertRaisesRegex(PlanError, "identity"):
            PreparedSync.from_dict(self.repo, value, expected_sync_id=value["sync_id"])

    def test_lost_db_ack_is_fenced_even_when_live_bytes_equal(self):
        self.setup_sync({}, {"x": b"x: 1"}, {})
        self.stage()
        self.client.lost_ack = True
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(self.client.documents, {"x": b"x: 1"})
        for recover in (False, True):
            with self.subTest(recover=recover), self.assertRaises(SyncUncertainError):
                self.execute(recover_db=recover)
        self.assertEqual(len(self.client.calls), 1, "UNCERTAIN_DB_MUST_NOT_RETRY")
        observed = observe_sync(
            self.repo,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
        )
        self.assertEqual(observed["database"], "db_unresolved")
        self.assertIsNone(observed["checkpoint"])

    def test_partial_db_fence_and_persistence_failures_never_dispatch(self):
        self.setup_sync({}, {"x": b"x: 1"}, {})
        self.stage()
        with self.store.directory(self.prepared.sync_id) as fd:
            import os

            marker = os.open("attempt.json", os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600, dir_fd=fd)
            os.close(marker)
        with self.assertRaises(PlanError):
            self.execute()
        self.assertEqual(self.client.calls, [], "PARTIAL_FENCE_MUST_BLOCK")

    def test_receipt_loss_after_db_commit_never_replays(self):
        self.setup_sync({}, {"x": b"x: 1"}, {})
        self.stage()
        original = self.store.put

        def put(intent, name, *args, **kwargs):
            if intent == self.prepared.sync_id and name == "receipt.json":
                raise OSError("synthetic DB receipt durability failure")
            return original(intent, name, *args, **kwargs)

        with patch.object(self.store, "put", put), self.assertRaises(SyncUncertainError):
            self.execute()
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(len(self.client.calls), 1)

    def test_lost_git_ack_observes_exact_signed_new_commit_without_republish(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {"x": b"x: 1"})
        self.stage()
        original = _Child.expect

        def expect(child, expected):
            original(child, expected)
            if expected == b"commit: ok\n":
                raise KeyboardInterrupt("synthetic lost Git acknowledgment")

        with patch.object(_Child, "expect", expect), self.assertRaises(GitPublishUncertainError):
            self.execute()
        new = self.tip()
        with patch(
            "yamora.gitops.sync.publish_git", side_effect=AssertionError("MUST_NOT_REPUBLISH")
        ):
            checkpoint = self.execute()
        self.assertEqual(checkpoint["baseline_commit"], new)
        self.assertEqual(self.client.calls, [])

    def test_git_aba_after_lost_ack_remains_unresolved(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {"x": b"x: 1"})
        self.stage()
        original = _Child.expect

        def expect(child, expected):
            original(child, expected)
            if expected == b"commit: ok\n":
                raise KeyboardInterrupt("synthetic lost acknowledgment")

        with patch.object(_Child, "expect", expect), self.assertRaises(GitPublishUncertainError):
            self.execute()
        self.git("update-ref", TARGET, self.current)
        with self.assertRaisesRegex(SyncUncertainError, "unresolved"):
            self.execute()
        self.assertEqual(self.tip(), self.current, "ABA_MUST_NOT_REPUBLISH")

    def test_new_db_edit_after_committed_phase_is_preserved_and_blocks_git(self):
        self.setup_sync(
            {"g": b"x: 0", "d": b"x: 0"},
            {"g": b"x: git", "d": b"x: 0"},
            {"g": b"x: 0", "d": b"x: db"},
        )
        self.stage()
        from yamora.gitops.apply import apply_prepared_db

        def apply(*args, **kwargs):
            result = apply_prepared_db(*args, **kwargs)
            self.client.documents["d"] = b"x: newer-authored-db"
            return result

        with (
            patch("yamora.gitops.sync.apply_prepared_db", side_effect=apply),
            self.assertRaisesRegex(PlanError, "diverges"),
        ):
            self.execute()
        self.assertEqual(self.client.documents["d"], b"x: newer-authored-db")
        self.assertEqual(self.client.documents["g"], b"x: git")
        self.assertEqual(self.tip(), self.current)
        with self.assertRaises(PlanError):
            self.execute()
        self.assertEqual(len(self.client.calls), 1)

    def test_resume_after_db_receipt_does_not_reapply_and_missing_key_is_irrelevant(self):
        self.setup_sync(
            {"g": b"x: 0", "d": b"x: 0"},
            {"g": b"x: git", "d": b"x: 0"},
            {"g": b"x: 0", "d": b"x: db"},
        )
        self.stage()
        with (
            patch("yamora.gitops.sync.publish_git", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.execute()
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(
            stage_sync(
                self.repo,
                self.prepared,
                artifacts=self.store,
                expected_sync_id=self.prepared.sync_id,
            ),
            self.staged,
        )
        self.execute()
        self.assertEqual(len(self.client.calls), 1)

    def test_stale_git_cas_preserves_other_actor_commit_and_no_checkpoint(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {"x": b"x: db"})
        self.stage()
        newer = self.commit({"x": b"x: other-author"})
        self.git("update-ref", TARGET, newer)
        with self.assertRaisesRegex(PlanError, "stale"):
            self.execute()
        self.assertEqual(self.tip(), newer)
        self.assertEqual(self.client.calls, [])

    def test_empty_cycle_never_needs_key_or_mutation_fences(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {"x": b"x: 0"})
        self.staged = stage_sync(
            self.repo, self.prepared, artifacts=self.store, expected_sync_id=self.prepared.sync_id
        )
        result = self.execute()
        self.assertEqual(result["baseline_commit"], self.current)
        self.assertEqual(self.client.calls, [])
        self.assertFalse(self.store.exists(self.prepared.sync_id, "attempt.json"))
        self.assertFalse(
            self.store.exists(self.prepared.to_dict()["prepared_git"]["intent_id"], "attempt.json")
        )

    def test_wrong_database_and_stage_ids_reject_before_db(self):
        self.setup_sync({}, {"x": b"x: 1"}, {})
        self.stage()
        with self.assertRaisesRegex(PlanError, "identity"):
            run_sync(
                self.client,
                self.repo,
                artifacts=self.store,
                expected_sync_id=self.prepared.sync_id,
                expected_staged_id=self.staged["staged_id"],
                database_id="e" * 32,
            )
        with self.assertRaisesRegex(PlanError, "identity"):
            run_sync(
                self.client,
                self.repo,
                artifacts=self.store,
                expected_sync_id=self.prepared.sync_id,
                expected_staged_id="0" * 64,
                database_id=DATABASE,
            )
        self.assertEqual(self.client.calls, [])

    def test_stale_ref_before_mixed_dispatch_preserves_db_and_git_authors(self):
        self.setup_sync(
            {"g": b"x: 0", "d": b"x: 0"},
            {"g": b"x: git", "d": b"x: 0"},
            {"g": b"x: 0", "d": b"x: db"},
        )
        self.stage()
        newer = self.commit({"g": b"x: newer-author", "d": b"x: 0"})
        self.git("update-ref", TARGET, newer)
        before = dict(self.client.documents)
        with self.assertRaisesRegex(PlanError, "stale"):
            self.execute()
        self.assertEqual(self.client.calls, [], "STALE_REF_MUST_PREVENT_DB_DISPATCH")
        self.assertEqual(self.client.documents, before)
        self.assertEqual(self.tip(), newer)

    def test_ref_move_during_standalone_preflight_prevents_transaction(self):
        self.setup_sync({}, {"x": b"# frozen Git\r\nx: 1\r\n"}, {})
        self.stage()
        newer = self.commit({"x": b"# newer author\nx: 2\n"})

        def export(*args, **kwargs):
            result = self.client.export()
            self.git("update-ref", TARGET, newer)
            return result

        with (
            patch("yamora.gitops.apply.capture_export", side_effect=export),
            self.assertRaises(PlanError),
        ):
            self.execute()
        self.assertEqual(self.client.calls, [], "PREFLIGHT_REF_MOVE_MUST_PREVENT_DB_SEND")
        self.assertEqual(self.client.documents, {})
        self.assertEqual(self.tip(), newer)
        self.assertTrue(self.store.exists(self.prepared.sync_id, "attempt.json"))
        self.assertFalse(self.store.exists(self.prepared.sync_id, "receipt.json"))

    def test_interrupted_coordinator_stage_reuses_saved_signature_without_key(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {"x": b"x: db"})
        original = self.store.put

        def put(intent, name, *args, **kwargs):
            if intent == self.prepared.sync_id and name == "staged.json":
                raise OSError("synthetic coordinator-stage crash")
            return original(intent, name, *args, **kwargs)

        with patch.object(self.store, "put", put), self.assertRaises(OSError):
            self.stage()
        self.assertEqual(self.client.calls, [])
        with patch(
            "yamora.gitops.sync.stage_git", side_effect=AssertionError("MUST_NOT_SIGN_AGAIN")
        ):
            self.staged = stage_sync(
                self.repo,
                self.prepared,
                artifacts=self.store,
                expected_sync_id=self.prepared.sync_id,
            )
        self.execute()

    def test_failed_attempt_barrier_leaves_positive_fence_and_sends_no_request(self):
        self.setup_sync({}, {"x": b"x: 1"}, {})
        self.stage()
        original = self.store.put

        def put(intent, name, *args, **kwargs):
            result = original(intent, name, *args, **kwargs)
            if name == "attempt.json":
                raise OSError("synthetic failed attempt barrier")
            return result

        with patch.object(self.store, "put", put), self.assertRaises(OSError):
            self.execute()
        self.assertTrue(self.store.exists(self.prepared.sync_id, "attempt.json"))
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(self.client.calls, [], "FAILED_FENCE_MUST_NOT_SEND")

    def test_two_mapping_owners_have_independent_opposite_directions(self):
        books = self.repo / "data/books"
        books.mkdir(parents=True)
        (books / "doc.yaml").write_bytes(b"x: book-old")
        base = self.commit({"person": b"x: person-old"})
        current = self.commit({"person": b"x: person-git"})
        self.git("update-ref", TARGET, current)
        exported = Export.from_dict(
            {
                "format": "yamora-gitops-export-v1",
                "revision": "0" * 16,
                "revision_scheme": "xor-fnv-v2",
                "scope": ["books", "people"],
                "collections": ["books", "people"],
                "documents": [
                    {
                        "collection": collection,
                        "document": document,
                        "etag": etag(source),
                        "source_b64": base64.b64encode(source).decode(),
                    }
                    for collection, document, source in (
                        ("books", "doc", b"x: book-db"),
                        ("people", "person", b"x: person-old"),
                    )
                ],
            }
        )
        mappings = [Mapping("books", "data/books"), *MAP]
        plan = build_plan(self.repo, base, current, exported, mappings)
        ownership = [
            {"collection": "books", "prefix": "data/books", "upstream": "db", "downstream": "git"},
            {**OWNERSHIP[0], "upstream": "git", "downstream": "db"},
        ]
        prepared = prepare_sync(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            database_id=DATABASE,
            operation_id="c" * 32,
            ownership=ownership,
            target_ref=TARGET,
            expected_old_commit=current,
            commit_metadata=META,
            signer_policy=self.public,
        )
        self.assertEqual(prepared.to_dict()["ownership"], ownership)
        self.assertEqual([e["target"] for e in plan["entries"]], ["git", "db"])
        ownership[0]["upstream"], ownership[0]["downstream"] = "git", "db"
        with self.assertRaisesRegex(PlanError, "ownership"):
            prepare_sync(
                self.repo,
                plan,
                expected_plan_id=plan["plan_id"],
                database_id=DATABASE,
                operation_id="c" * 32,
                ownership=ownership,
                target_ref=TARGET,
                expected_old_commit=current,
                commit_metadata=META,
                signer_policy=self.public,
            )

    def test_checkpoint_durability_failure_resumes_without_duplicate_effects(self):
        self.setup_sync(
            {"g": b"x: 0", "d": b"x: 0"},
            {"g": b"x: git", "d": b"x: 0"},
            {"g": b"x: 0", "d": b"x: db"},
        )
        self.stage()
        original = self.store.put
        git_id = self.prepared.to_dict()["prepared_git"]["intent_id"]

        def put(intent, name, *args, **kwargs):
            if intent not in (self.prepared.sync_id, git_id) and name == "receipt.json":
                raise OSError("synthetic checkpoint barrier failure")
            return original(intent, name, *args, **kwargs)

        with patch.object(self.store, "put", put), self.assertRaises(OSError):
            self.execute()
        new = self.tip()
        self.assertNotEqual(new, self.current)
        with patch(
            "yamora.gitops.sync.publish_git", side_effect=AssertionError("MUST_NOT_REPUBLISH")
        ):
            checkpoint = self.execute()
        self.assertEqual(checkpoint["baseline_commit"], new)
        self.assertEqual(len(self.client.calls), 1)

    def test_rehashed_checkpoint_cannot_claim_another_common_baseline(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {"x": b"x: db"})
        self.stage()
        checkpoint = self.execute()
        checkpoint["baseline_commit"] = self.current
        checkpoint["checkpoint_id"] = digest(
            canonical({k: v for k, v in checkpoint.items() if k != "checkpoint_id"})
        )
        directory = digest(canonical(["yamora-gitops-sync-checkpoint-v1", self.prepared.sync_id]))
        (self.artifacts / directory / "receipt.json").write_bytes(canonical(checkpoint) + b"\n")
        with self.assertRaisesRegex(PlanError, "checkpoint identity"):
            observe_sync(
                self.repo,
                artifacts=self.store,
                expected_sync_id=self.prepared.sync_id,
                expected_staged_id=self.staged["staged_id"],
            )
