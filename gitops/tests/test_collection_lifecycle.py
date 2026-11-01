"""Opt-in collection lifecycle planning, publication and synchronization guarantees."""

import base64
import copy
import json
import unittest
from unittest.mock import patch

from yamora.gitops.apply import prepare_db
from yamora.gitops.git_apply import GitPublishUncertainError
from yamora.gitops.git_apply import prepare_git
from yamora.gitops.git_apply import publish_git
from yamora.gitops.git_apply import stage_git
from yamora.gitops.git_artifacts import GitArtifacts
from yamora.gitops.git_writer import _Child
from yamora.gitops.model import Export
from yamora.gitops.model import Limits
from yamora.gitops.model import PlanError
from yamora.gitops.model import canonical
from yamora.gitops.model import digest
from yamora.gitops.model import etag
from yamora.gitops.planner import build_plan
from yamora.gitops.sync import SyncUncertainError
from yamora.gitops.sync import observe_sync
from yamora.gitops.sync import plan_from_checkpoint
from yamora.gitops.sync import prepare_sync
from yamora.gitops.sync import run_sync
from yamora.gitops.sync import stage_sync
from yamora.gitops.tests.test_git_apply import reidentify
from yamora.gitops.tests.test_git_signing import META
from yamora.gitops.tests.test_git_signing import TARGET
from yamora.gitops.tests.test_git_signing import SyntheticGit
from yamora.gitops.tests.test_sync import DATABASE
from yamora.gitops.tests.test_sync import MAP
from yamora.gitops.tests.test_sync import OWNERSHIP
from yamora.gitops.tests.test_sync import ModelDB

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
REQUEST = "1" * 32
# A collection far above the 128-operation transaction and Git change bounds.
MANY = 3000
LARGE = Limits(max_documents=MANY + 8, deadline=300)
PURGE = {"collection": "people", "drop_collection": True, "purge": True}


def many(extra=b""):
    return {f"p-{n:05}": b"# exact\r\nn: %d\r\n" % n + extra for n in range(MANY)}


def exported(documents, present, limits=None):
    revision = digest(canonical([sorted((k, v.hex()) for k, v in documents.items()), present]))
    return Export.from_dict(
        {
            "format": "yamora-gitops-export-v1",
            "revision": revision[:16],
            "revision_scheme": "xor-fnv-v2",
            "scope": ["people"],
            "collections": ["people"] if present else [],
            "documents": [
                {
                    "collection": "people",
                    "document": name,
                    "etag": etag(source),
                    "source_b64": base64.b64encode(source).decode(),
                }
                for name, source in sorted(documents.items())
            ],
        },
        limits,
    )


class LifecycleDB(ModelDB):
    """Strict synthetic catalog: puts create, drops require the batch to empty it
    unless they purge, which owns the whole collection under the batch revision."""

    def __init__(self, documents, present, limits=None):
        super().__init__(documents)
        self.collections_present = present
        self.limits = limits

    def export(self):
        return exported(self.documents, self.collections_present, self.limits)

    def _request(self, path, **kwargs):
        self.calls.append((path, kwargs))
        request = json.loads(kwargs["body"])
        if request["revision"] != self.export().revision:
            raise AssertionError("synthetic fixture rejected stale request")
        documents, present, lifecycle = dict(self.documents), self.collections_present, []
        for operation in request["operations"]:
            if "document" not in operation:
                lifecycle.append(operation)
            elif "put" in operation:
                documents[operation["document"]] = operation["put"].encode()
                present = True
            else:
                documents.pop(operation["document"])
        purged = [o for o in lifecycle if o.get("purge") is True]
        if purged and (len(purged) != len(lifecycle) or len(request["operations"]) != 1):
            raise AssertionError("synthetic purge must own its whole collection")
        for operation in lifecycle:
            if operation.get("purge") is True and operation.get("drop_collection") and present:
                documents, present = {}, False
            elif operation.get("drop_collection") is True and present and not documents:
                present = False
            elif operation.get("create_collection") is True and not present:
                present = True
            else:
                raise AssertionError("synthetic native collection operation rejected")
        self.documents, self.collections_present = documents, present
        if self.lost_ack:
            raise OSError("synthetic lost DB acknowledgment")
        receipt = {
            "status": "committed",
            "operations": len(request["operations"]),
            "revision": self.export().revision,
        }
        return canonical(receipt), "application/json", {"x-yamldb-revision": receipt["revision"]}


class ExactTrees(SyntheticGit):
    limits = None

    def lifecycle_plan(self, base, selected, db, present):
        self.base = self.exact(base)
        self.current = self.exact(selected)
        return build_plan(
            self.repo,
            self.base,
            self.current,
            exported(db, present, self.limits),
            MAP,
            limits=self.limits,
            collection_lifecycle=True,
        )


class CollectionPlanTests(ExactTrees, unittest.TestCase):
    def operations(self, plan):
        frozen = prepare_db(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            request_id=REQUEST,
            limits=self.limits,
        )
        return frozen, json.loads(frozen.body)

    def test_default_plan_format_and_decisions_are_unchanged(self):
        base, current = self.exact({"x": b"x: 0"}), self.exact(None)
        export = exported({"x": b"x: 0"}, True)
        plan = build_plan(self.repo, base, current, export, MAP)
        self.assertEqual(
            plan, build_plan(self.repo, base, current, export, MAP, collection_lifecycle=False)
        )
        self.assertEqual(plan["format"], "yamora-gitops-plan-v1")
        self.assertEqual(
            set(plan), {"format", "read_only", "preconditions", "summary", "entries", "plan_id"}
        )
        frozen, body = self.operations(plan)
        self.assertEqual(
            body["operations"],
            [{"collection": "people", "document": "x", "delete": True, "etag": etag(b"x: 0")}],
            "V1_MUST_NEVER_DROP_COLLECTION_METADATA",
        )

    def test_presence_matrix_is_an_exact_three_way_tree_and_catalog_decision(self):
        cases = (
            ((None, None, False), ("unchanged", "none")),
            ((None, None, True), ("add", "git")),
            ((None, {}, False), ("add", "db")),
            ((None, {}, True), ("converged", "none")),
            (({}, None, False), ("converged", "none")),
            (({}, None, True), ("delete", "db")),
            (({}, {}, False), ("delete", "git")),
            (({}, {}, True), ("unchanged", "none")),
        )
        for (base, selected, present), (status, target) in cases:
            with self.subTest(base=base, selected=selected, present=present):
                plan = self.lifecycle_plan(base, selected, {}, present)
                self.assertEqual(plan["format"], "yamora-gitops-plan-v2")
                self.assertEqual(plan["entries"], [])
                self.assertEqual(
                    plan["collections"],
                    [
                        {
                            "collection": "people",
                            "prefix": "data/people",
                            "status": status,
                            "target": target,
                            "baseline": {"present": base is not None},
                            "git": {
                                "present": selected is not None,
                                "tree_oid": EMPTY_TREE if selected is not None else None,
                            },
                            "db": {"present": present},
                        }
                    ],
                )
                summary = dict.fromkeys(("add", "delete", "conflict", "unchanged", "converged"), 0)
                self.assertEqual(plan["collection_summary"], {**summary, status: 1})

    def test_collection_removal_conflicts_with_any_other_side_document_change(self):
        x = b"# exact\r\nx: 0\r\n"
        cases = (
            ({"x": x}, None, {"x": x, "y": b"y: db"}, True),
            ({"x": x}, None, {"x": b"x: db"}, True),
            ({"x": x}, {"x": x, "y": b"y: git"}, {}, False),
            ({"x": x}, {"x": b"x: git"}, {}, False),
        )
        for base, selected, db, present in cases:
            with self.subTest(selected=selected, db=db):
                plan = self.lifecycle_plan(base, selected, db, present)
                self.assertEqual(plan["collections"][0]["status"], "conflict")
                self.assertEqual(plan["collections"][0]["target"], "none")
                self.assertEqual(plan["collection_summary"]["conflict"], 1)
                with self.assertRaisesRegex(PlanError, "conflict"):
                    self.operations(plan)

    def test_git_directory_removal_freezes_one_revision_guarded_purge(self):
        docs = {"x": b"# exact\r\nx: 0\r\n", "y": b"y: 1"}
        plan = self.lifecycle_plan(docs, None, docs, True)
        self.assertEqual([e["status"] for e in plan["entries"]], ["delete", "delete"])
        self.assertEqual(plan["collections"][0]["status"], "delete")
        self.assertEqual(plan["collections"][0]["target"], "db")
        frozen, body = self.operations(plan)
        self.assertEqual(
            body["operations"],
            [{"collection": "people", "drop_collection": True, "purge": True}],
        )
        self.assertEqual(body["revision"], plan["preconditions"]["db"]["revision"])
        self.assertEqual(frozen.operation_count, 1)
        self.assertEqual(frozen.pending_git, ())

    def test_large_git_directory_removal_is_one_purge_while_ordinary_batches_stay_bounded(self):
        self.limits = LARGE
        docs = many()
        plan = self.lifecycle_plan(docs, None, docs, True)
        self.assertEqual(len(plan["entries"]), MANY)
        self.assertEqual(plan["collections"][0]["status"], "delete")
        frozen, body = self.operations(plan)
        self.assertEqual(
            body, {"operations": [PURGE], "revision": plan["preconditions"]["db"]["revision"]}
        )
        self.assertEqual(frozen.operation_count, 1)
        # Emptying the tree but keeping it deletes documents, not the collection:
        # an ordinary batch keeps the 128-operation bound and is never chunked.
        kept = self.lifecycle_plan(docs, {}, docs, True)
        self.assertEqual(kept["collections"][0]["status"], "unchanged")
        with self.assertRaisesRegex(PlanError, "exceeds 128 operations"):
            self.operations(kept)

    def test_empty_git_tree_creates_an_empty_collection_and_puts_create_implicitly(self):
        _, body = self.operations(self.lifecycle_plan(None, {}, {}, False))
        self.assertEqual(body["operations"], [{"collection": "people", "create_collection": True}])
        plan = self.lifecycle_plan(None, {"x": b"x: 1"}, {}, False)
        self.assertEqual(plan["collections"][0]["status"], "add")
        _, body = self.operations(plan)
        self.assertEqual(
            body["operations"],
            [{"collection": "people", "document": "x", "put": "x: 1", "create_only": True}],
        )

    def test_database_side_drop_and_create_are_pending_git_changes(self):
        x = b"x: 0\n"
        frozen, _ = self.operations(self.lifecycle_plan({"x": x}, {"x": x}, {}, False))
        self.assertEqual(frozen.operation_count, 0)
        # The whole prefix tree is one pending removal, whatever it holds.
        self.assertEqual(frozen.pending_git, ("data/people",))
        frozen, _ = self.operations(self.lifecycle_plan(None, None, {}, True))
        self.assertEqual(frozen.pending_git, ("data/people",))

    def test_tampered_or_mixed_format_collection_metadata_fails_closed(self):
        plan = self.lifecycle_plan({}, None, {}, True)
        mutations = (
            lambda p: p["collections"][0].update(status="unchanged", target="none"),
            lambda p: p["collections"][0].update(target="git"),
            lambda p: p["collections"][0]["git"].update(tree_oid=EMPTY_TREE),
            lambda p: p["collections"][0]["db"].update(present=False),
            lambda p: p["collections"][0].update(extra=True),
            lambda p: p["collections"][0].update(prefix="data/other"),
            lambda p: p["collections"].append(copy.deepcopy(p["collections"][0])),
            lambda p: p.pop("collections"),
            lambda p: p["collection_summary"].update(delete=0, unchanged=1),
            lambda p: p.update(format="yamora-gitops-plan-v1"),
        )
        for number, mutate in enumerate(mutations):
            value = copy.deepcopy(plan)
            mutate(value)
            reidentify(value, "plan_id")
            with self.subTest(number=number), self.assertRaises(PlanError):
                prepare_db(self.repo, value, expected_plan_id=value["plan_id"], request_id=REQUEST)
        legacy = build_plan(self.repo, self.base, self.current, exported({}, True), MAP)
        legacy["collections"] = plan["collections"]
        reidentify(legacy, "plan_id")
        with self.assertRaises(PlanError):
            prepare_db(self.repo, legacy, expected_plan_id=legacy["plan_id"], request_id=REQUEST)


class CollectionPublicationTests(ExactTrees, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.key, self.public = self.make_key()
        self.store = GitArtifacts(self.artifacts)
        self.addCleanup(self.store.close)

    def publish(self, base, selected, db, present, operation="1" * 32):
        plan = self.lifecycle_plan(base, selected, db, present)
        self.git("update-ref", TARGET, self.current)
        prepared = prepare_git(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            target_ref=TARGET,
            expected_old_commit=self.current,
            operation_id=operation,
            commit_metadata=META,
            signer_policy=self.public,
            limits=self.limits,
        )
        staged = stage_git(
            self.repo,
            prepared,
            artifacts=self.store,
            expected_intent_id=prepared.intent_id,
            signer_config=self.key,
            limits=self.limits,
        )
        result = publish_git(
            self.repo,
            staged,
            artifacts=self.store,
            expected_intent_id=staged.intent_id,
            expected_staged_id=staged.staged_id,
            limits=self.limits,
        )
        tip = self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode()
        self.assertEqual(result["new_commit"], tip)
        self.assertEqual(self.git("rev-parse", tip + "^").stdout.strip().decode(), self.current)
        return result, tip

    def test_database_drop_removes_the_exact_tree_and_preserves_siblings(self):
        docs = {"x": b"# exact\r\nx: 0\r\n", "y": b"y: 1"}
        result, tip = self.publish(docs, docs, {}, False)
        before, after = self.listing(self.current), self.listing(tip)
        self.assertEqual(result["status"], "git_published")
        self.assertEqual(result["operation_count"], 1)
        self.assertEqual(result["pending_db"], [])
        # Every sibling blob and tree keeps its exact OID; only the parent changes.
        self.assertEqual(
            {
                path: value
                for path, value in before.items()
                if "people" not in path and path != "data"
            },
            {path: value for path, value in after.items() if path != "data"},
        )
        self.assertFalse(any("people" in path for path in after))
        self.assertEqual(after["data"][0], "040000")

    def test_large_database_drop_removes_the_whole_tree_as_one_change(self):
        self.limits = LARGE
        result, tip = self.publish(many(), many(), {}, False)
        self.assertEqual(result["operation_count"], 1)
        before, after = self.listing(self.current), self.listing(tip)
        self.assertEqual(len([p for p in before if p.startswith("data/people/")]), MANY)
        self.assertFalse(any("people" in path for path in after))
        self.assertEqual(after["data/keep.txt"], before["data/keep.txt"])
        self.assertEqual(after["README.md"], before["README.md"])

    def test_created_or_emptied_database_collection_is_an_exact_empty_tree(self):
        for number, (base, selected, db, present, count) in enumerate(
            ((None, None, {}, True, 1), ({"x": b"x: 0"}, {"x": b"x: 0"}, {}, True, 1))
        ):
            with self.subTest(base=base):
                result, tip = self.publish(base, selected, db, present, str(number + 1) * 32)
                self.assertEqual(result["operation_count"], count)
                self.assertEqual(self.listing(tip)["data/people"], ("040000", EMPTY_TREE))
                self.assertNotIn("data/people/x.yaml", self.listing(tip))


class CollectionSyncTests(ExactTrees, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.key, self.public = self.make_key()
        self.store = GitArtifacts(self.artifacts)
        self.addCleanup(self.store.close)
        for target in ("yamora.gitops.sync.capture_export", "yamora.gitops.apply.capture_export"):
            patcher = patch(target, side_effect=lambda client, *a, **k: client.export())
            patcher.start()
            self.addCleanup(patcher.stop)

    def setup_sync(self, base, selected, db, present, ownership=None):
        self.client = LifecycleDB(db, present, self.limits)
        self.current = self.exact(selected)
        self.plan = build_plan(
            self.repo,
            self.exact(base),
            self.current,
            self.client.export(),
            MAP,
            limits=self.limits,
            collection_lifecycle=True,
        )
        self.git("update-ref", TARGET, self.current)
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
            limits=self.limits,
        )
        self.staged = stage_sync(
            self.repo,
            self.prepared,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            signer_config=self.key,
            limits=self.limits,
        )

    def execute(self, **kwargs):
        return run_sync(
            self.client,
            self.repo,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            database_id=DATABASE,
            limits=self.limits,
            **kwargs,
        )

    def observe(self):
        return observe_sync(
            self.repo,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            limits=self.limits,
        )

    def next_plan(self, checkpoint, **kwargs):
        return plan_from_checkpoint(
            self.repo,
            self.tip(),
            self.client.export(),
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            expected_checkpoint_id=checkpoint["checkpoint_id"],
            limits=self.limits,
            **kwargs,
        )

    def tip(self):
        return self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode()

    def test_git_removed_collection_is_dropped_once_and_checkpointed_absent(self):
        docs = {"x": b"# exact\nx: 0\n", "y": b"y: 1"}
        self.setup_sync(docs, None, docs, True)
        checkpoint = self.execute()
        self.assertEqual(self.client.documents, {})
        self.assertFalse(self.client.collections_present)
        self.assertEqual(len(self.client.calls), 1)
        operations = json.loads(self.client.calls[0][1]["body"])["operations"]
        self.assertEqual(
            operations, [{"collection": "people", "drop_collection": True, "purge": True}]
        )
        self.assertEqual(self.tip(), self.current, "GIT_SIDE_ALREADY_HOLDS_THE_RESULT")
        self.assertEqual(checkpoint["export"]["collections"], [])
        self.assertEqual(self.execute(), checkpoint)
        self.assertEqual(len(self.client.calls), 1, "RESTART_MUST_NOT_REPEAT_DROP")
        following = self.next_plan(checkpoint)
        self.assertEqual(following["format"], "yamora-gitops-plan-v2")
        self.assertEqual(following["collections"][0]["status"], "unchanged")
        self.assertFalse(following["collections"][0]["git"]["present"])

    def test_database_drop_removes_git_tree_through_signed_publication(self):
        docs = {"x": b"x: 0\n", "y": b"# exact\r\ny: 1\r\n"}
        self.setup_sync(docs, docs, {}, False)
        checkpoint = self.execute()
        self.assertEqual(self.client.calls, [])
        tip = self.tip()
        self.assertEqual(checkpoint["baseline_commit"], tip)
        self.assertEqual(self.git("rev-parse", tip + "^").stdout.strip().decode(), self.current)
        listing = self.listing(tip)
        self.assertFalse(any("people" in path for path in listing))
        self.assertEqual(listing["data/keep.txt"], self.listing(self.current)["data/keep.txt"])
        following = self.next_plan(checkpoint)
        self.assertEqual(following["collections"][0]["status"], "unchanged")
        self.assertEqual(following["summary"]["delete"], 0)

    def test_large_collection_removal_syncs_both_directions_once_with_checkpoints(self):
        self.limits = LARGE
        docs = many()
        for removed_from, selected, db, present in (
            ("git", None, docs, True),
            ("db", docs, {}, False),
        ):
            with self.subTest(removed_from=removed_from):
                self.setup_sync(docs, selected, db, present)
                checkpoint = self.execute()
                self.assertEqual(self.client.documents, {})
                self.assertFalse(self.client.collections_present)
                self.assertEqual(checkpoint["export"]["collections"], [])
                self.assertFalse(any("people" in path for path in self.listing(self.tip())))
                if removed_from == "git":
                    self.assertEqual(len(self.client.calls), 1)
                    self.assertEqual(
                        json.loads(self.client.calls[0][1]["body"])["operations"], [PURGE]
                    )
                    self.assertEqual(self.tip(), self.current)
                else:
                    self.assertEqual(self.client.calls, [])
                    self.assertEqual(
                        self.git("rev-parse", self.tip() + "^").stdout.strip().decode(),
                        self.current,
                    )
                self.assertEqual(checkpoint["baseline_commit"], self.tip())
                self.assertEqual(self.execute(), checkpoint)
                self.assertEqual(
                    len(self.client.calls), removed_from == "git", "NO_REPEATED_EFFECT"
                )

    def test_large_purge_after_drift_or_a_lost_acknowledgment_is_never_redispatched(self):
        self.limits = LARGE
        docs = many()
        self.setup_sync(docs, None, docs, True)
        self.client.documents["late"] = b"# racing writer\nlate: 1\n"
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(self.client.calls, [], "DRIFTED_EXPORT_MUST_PREVENT_PURGE")
        self.assertEqual(len(self.client.documents), MANY + 1)
        self.assertTrue(self.client.collections_present)
        self.setup_sync(docs, None, docs, True)
        self.client.lost_ack = True
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertFalse(self.client.collections_present)
        for recover in (False, True):
            with self.subTest(recover=recover), self.assertRaises(SyncUncertainError):
                self.execute(recover_db=recover)
        self.assertEqual(len(self.client.calls), 1, "UNCERTAIN_PURGE_MUST_NOT_RETRY")
        self.assertEqual(self.observe()["database"], "db_unresolved")

    def test_lost_drop_acknowledgment_stays_fenced_without_redispatch(self):
        self.setup_sync({"x": b"x: 0"}, None, {"x": b"x: 0"}, True)
        self.client.lost_ack = True
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertFalse(self.client.collections_present)
        for recover in (False, True):
            with self.subTest(recover=recover), self.assertRaises(SyncUncertainError):
                self.execute(recover_db=recover)
        self.assertEqual(len(self.client.calls), 1, "UNCERTAIN_DROP_MUST_NOT_RETRY")
        observed = self.observe()
        self.assertEqual(observed["database"], "db_unresolved")
        self.assertIsNone(observed["checkpoint"])

    def test_lost_tree_removal_acknowledgment_recovers_without_republishing(self):
        self.setup_sync({"x": b"x: 0"}, {"x": b"x: 0"}, {}, False)
        original = _Child.expect

        def expect(child, expected):
            original(child, expected)
            if expected == b"commit: ok\n":
                raise KeyboardInterrupt("synthetic lost Git acknowledgment")

        with patch.object(_Child, "expect", expect), self.assertRaises(GitPublishUncertainError):
            self.execute()
        new = self.tip()
        self.assertNotIn("data/people", self.listing(new))
        with patch(
            "yamora.gitops.sync.publish_git", side_effect=AssertionError("MUST_NOT_REPUBLISH")
        ):
            checkpoint = self.execute()
        self.assertEqual(checkpoint["baseline_commit"], new)

    def test_one_way_ownership_rejects_a_drop_from_the_excluded_side(self):
        x = {"x": b"x: 0"}
        # The last two change only collection metadata: no document entry exists.
        for upstream, downstream, base, selected, db, present in (
            ("git", "db", x, x, {}, False),
            ("db", "git", x, None, x, True),
            ("git", "db", {}, {}, {}, False),
            ("db", "git", {}, None, {}, True),
            ("git", "db", None, None, {}, True),
            ("db", "git", None, {}, {}, False),
        ):
            ownership = [{**OWNERSHIP[0], "upstream": upstream, "downstream": downstream}]
            with (
                self.subTest(upstream=upstream, base=base, selected=selected, present=present),
                self.assertRaisesRegex(PlanError, "ownership"),
            ):
                self.setup_sync(base, selected, db, present, ownership)
            self.assertEqual(self.client.calls, [])
        # The permitted direction of the same metadata-only drop is accepted.
        self.setup_sync(
            {}, None, {}, True, [{**OWNERSHIP[0], "upstream": "git", "downstream": "db"}]
        )
        self.execute()
        self.assertFalse(self.client.collections_present)

    def test_document_added_after_reviewed_drop_is_preserved(self):
        self.setup_sync({"x": b"x: 0"}, None, {"x": b"x: 0"}, True)
        self.client.documents["y"] = b"# racing writer\ny: 1\n"
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(self.client.calls, [], "DRIFTED_EXPORT_MUST_PREVENT_DROP")
        self.assertTrue(self.client.collections_present)
        self.assertEqual(self.client.documents["y"], b"# racing writer\ny: 1\n")
        self.assertTrue(self.store.exists(self.prepared.sync_id, "attempt.json"))

    def test_receipt_loss_after_committed_drop_never_replays(self):
        self.setup_sync({"x": b"x: 0"}, None, {"x": b"x: 0"}, True)
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

    def test_presence_disagreeing_checkpoint_cannot_seed_lifecycle_plans(self):
        self.client = LifecycleDB({"x": b"x: 0"}, True)
        base, current = self.exact({"x": b"x: 0"}), self.exact(None)
        self.plan = build_plan(self.repo, base, current, self.client.export(), MAP)
        self.current = current
        self.git("update-ref", TARGET, current)
        self.prepared = prepare_sync(
            self.repo,
            self.plan,
            expected_plan_id=self.plan["plan_id"],
            database_id=DATABASE,
            operation_id="a" * 32,
            ownership=OWNERSHIP,
            target_ref=TARGET,
            expected_old_commit=current,
            commit_metadata=META,
            signer_policy=self.public,
        )
        self.staged = stage_sync(
            self.repo,
            self.prepared,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            signer_config=self.key,
        )
        checkpoint = self.execute()
        self.assertTrue(self.client.collections_present, "V1_KEEPS_EMPTY_COLLECTION")
        self.assertEqual(self.next_plan(checkpoint)["format"], "yamora-gitops-plan-v1")
        with self.assertRaisesRegex(PlanError, "collection"):
            self.next_plan(checkpoint, collection_lifecycle=True)


if __name__ == "__main__":
    unittest.main()
