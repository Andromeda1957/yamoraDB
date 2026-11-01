"""Real synthetic signed publication, CAS races and persisted recovery semantics."""

import base64
import copy
import os
import unittest
from unittest.mock import patch

from yamora.gitops.git_apply import GitPublishUncertainError
from yamora.gitops.git_apply import PreparedGit
from yamora.gitops.git_apply import StagedGit
from yamora.gitops.git_apply import prepare_git
from yamora.gitops.git_apply import publish_git
from yamora.gitops.git_apply import recover_git
from yamora.gitops.git_apply import stage_git
from yamora.gitops.git_artifacts import GitArtifacts
from yamora.gitops.git_writer import GitCommandError
from yamora.gitops.git_writer import GitInfrastructureError
from yamora.gitops.git_writer import GitWriter
from yamora.gitops.git_writer import _Child
from yamora.gitops.model import Export
from yamora.gitops.model import Limits
from yamora.gitops.model import Mapping
from yamora.gitops.model import PlanError
from yamora.gitops.model import canonical
from yamora.gitops.model import digest
from yamora.gitops.model import etag
from yamora.gitops.planner import build_plan
from yamora.gitops.tests.test_git_signing import META
from yamora.gitops.tests.test_git_signing import TARGET
from yamora.gitops.tests.test_git_signing import SyntheticGit

MAP = [Mapping("people", "data/people")]


def exported(documents):
    return Export.from_dict(
        {
            "format": "yamora-gitops-export-v1",
            "revision": "0123456789abcdef",
            "revision_scheme": "xor-fnv-v2",
            "scope": ["people"],
            "collections": ["people"],
            "documents": [
                {
                    "collection": "people",
                    "document": name,
                    "etag": etag(source),
                    "source_b64": base64.b64encode(source).decode(),
                }
                for name, source in sorted(documents.items())
            ],
        }
    )


def reidentify(value, field):
    value[field] = digest(canonical({k: v for k, v in value.items() if k != field}))
    return value


class GitApplyTests(SyntheticGit, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.key, self.public = self.make_key()
        self.store = GitArtifacts(self.artifacts)
        self.addCleanup(self.store.close)

    def intent(self, baseline, selected, db):
        base = self.commit(baseline)
        current = self.commit(selected)
        self.git("update-ref", TARGET, current)
        plan = build_plan(self.repo, base, current, exported(db), MAP)
        return self.prepare(plan, current), plan, current

    def prepare(self, plan, current, **kwargs):
        return prepare_git(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            target_ref=TARGET,
            expected_old_commit=current,
            operation_id="1" * 32,
            commit_metadata=META,
            signer_policy=self.public,
            **kwargs,
        )

    def stage(self, prepared):
        return stage_git(
            self.repo,
            prepared,
            artifacts=self.store,
            expected_intent_id=prepared.intent_id,
            signer_config=self.key,
        )

    def publish(self, staged):
        return publish_git(
            self.repo,
            staged,
            artifacts=self.store,
            expected_intent_id=staged.intent_id,
            expected_staged_id=staged.staged_id,
        )

    def recover(self, staged):
        return recover_git(
            self.repo,
            staged,
            artifacts=self.store,
            expected_intent_id=staged.intent_id,
            expected_staged_id=staged.staged_id,
        )

    def tip(self):
        return self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode()

    def lost_ack(self, staged):
        original = _Child.expect

        def expect(child, expected):
            original(child, expected)
            if expected == b"commit: ok\n":
                raise KeyboardInterrupt("synthetic lost acknowledgment")

        with patch.object(_Child, "expect", expect), self.assertRaises(GitPublishUncertainError):
            self.publish(staged)
        self.assertEqual(self.tip(), staged.to_dict()["commit_oid"])

    def test_real_signed_exact_add_update_delete_preserves_checkout_and_other_files(self):
        (self.repo / "unmapped").write_bytes(b"outside\x00source")
        (self.repo / "executable").write_bytes(b"#!/synthetic\n")
        (self.repo / "executable").chmod(0o755)
        (self.repo / "link").symlink_to("unmapped")
        old = {"change": b"x: 1\n", "delete": b"x: old\n", "steady": b"x: steady\n"}
        replacement = "# comment\r\nname: 'Zoë' # exact\r\n".encode()
        prepared, plan, current = self.intent(
            old,
            old,
            {
                "change": replacement,
                "add": b"x: 2",
                "steady": old["steady"],
            },
        )
        index = (self.repo / ".git/index").read_bytes()
        staged = self.stage(prepared)
        self.assertEqual(self.tip(), current, "STAGE_MUST_NOT_PUBLISH")
        result = self.publish(staged)
        self.assertEqual(result["status"], "git_published")
        self.assertEqual(result["operation_count"], 3)
        new = result["new_commit"]
        self.assertEqual(self.tip(), new)
        self.assertEqual(self.git("rev-parse", new + "^").stdout.strip().decode(), current)
        self.assertEqual(self.git("show", new + ":data/people/change.yaml").stdout, replacement)
        self.assertEqual(self.git("show", new + ":data/people/add.yaml").stdout, b"x: 2")
        self.assertNotEqual(
            self.git("cat-file", "-e", new + ":data/people/delete.yaml", check=False).returncode, 0
        )
        for name in ("unmapped", "executable", "link"):
            self.assertEqual(
                self.git("ls-tree", current, "--", name).stdout,
                self.git("ls-tree", new, "--", name).stdout,
            )
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip().decode(), current)
        self.assertEqual((self.repo / ".git/index").read_bytes(), index)
        self.assertEqual((self.repo / "data/people/change.yaml").read_bytes(), old["change"])
        self.assertEqual(self.recover(staged)["status"], "publication_recorded")

    def test_three_way_conflicts_and_rehashed_wrong_decisions_reject_before_writes(self):
        for base, selected, db in (
            ({}, {"x": b"x: 1"}, {"x": b"x: 2"}),
            ({"x": b"x: 1"}, {}, {"x": b"x: 2"}),
            ({"x": b"x: 1\n"}, {"x": b"x: 1\r\n"}, {"x": b"# c\nx: 1\n"}),
        ):
            with self.subTest(base=base), self.assertRaisesRegex(PlanError, "conflict"):
                self.intent(base, selected, db)
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        changed = copy.deepcopy(plan)
        changed["entries"][0]["target"] = "db"
        reidentify(changed, "plan_id")
        with self.assertRaisesRegex(PlanError, "derived"):
            self.prepare(changed, current)
        with self.assertRaisesRegex(PlanError, "identity"):
            PreparedGit.from_dict(self.repo, prepared.to_dict(), expected_intent_id="0" * 64)

    def test_same_tree_different_commit_cannot_replace_expected_parent_identity(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        tree = self.git("rev-parse", current + "^{tree}").stdout.strip().decode()
        other = (
            self.git("commit-tree", tree, "-p", current, data=b"other parent\n")
            .stdout.strip()
            .decode()
        )
        with self.assertRaisesRegex(PlanError, "stale"):
            self.prepare(plan, other)
        self.assertEqual(self.tip(), current)

    def test_real_competing_cas_rejects_stale_old_without_fence(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        tree = self.git("rev-parse", current + "^{tree}").stdout.strip().decode()
        other = (
            self.git("commit-tree", tree, "-p", current, data=b"competitor\n")
            .stdout.strip()
            .decode()
        )
        original = _Child.send
        moved = []

        def send(child, data):
            if data.startswith(b"option no-deref\0update ") and not moved:
                self.git("update-ref", TARGET, other, current)
                moved.append(True)
            return original(child, data)

        rejected = None
        try:
            with patch.object(_Child, "send", send):
                self.publish(staged)
        except PlanError as error:
            rejected = error
        self.assertTrue(moved, "CAS_DISPATCH_WITNESS")
        self.assertEqual(self.tip(), other, "STALE_CAS_OVERWROTE_COMPETITOR")
        self.assertIsNotNone(rejected, "CAS_REJECTION_MISSING")
        self.assertNotIsInstance(rejected, GitPublishUncertainError)
        self.assertFalse(self.store.exists(prepared.intent_id, "attempt.json"))

    def test_symbolic_substitution_before_prepare_cannot_redirect_publication(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        original = _Child.send
        moved = []

        def send(child, data):
            if data.startswith(b"option no-deref\0update ") and not moved:
                self.git("symbolic-ref", TARGET, "refs/heads/fixture")
                moved.append(True)
            return original(child, data)

        with patch.object(_Child, "send", send), self.assertRaises(PlanError):
            self.publish(staged)
        self.assertEqual(
            self.git("symbolic-ref", "--quiet", TARGET).stdout.strip(),
            b"refs/heads/fixture",
            "SYMBOLIC_REF_REPLACED",
        )
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip().decode(), current)
        self.assertFalse(self.store.exists(prepared.intent_id, "attempt.json"))

    def test_real_lost_ack_recovers_original_commit_without_signing_or_writing(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        self.lost_ack(staged)
        self.assertFalse(self.store.exists(prepared.intent_id, "receipt.json"))
        original = GitWriter.run

        def read_only(writer, args, **kwargs):
            self.assertNotIn(
                args[0],
                ("hash-object", "mktree", "commit-tree", "update-ref"),
                "RECOVERY_MUTATED_GIT",
            )
            return original(writer, args, **kwargs)

        with patch.object(GitWriter, "run", read_only):
            result = self.recover(staged)
        self.assertEqual(result["status"], "publication_observed")
        self.assertEqual(result["observed_ref_oid"], staged.to_dict()["commit_oid"])

    def test_old_tip_after_aba_remains_unresolved_and_never_redispatches(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        self.lost_ack(staged)
        self.git("update-ref", TARGET, current)
        result = self.recover(staged)
        self.assertEqual(result["status"], "publication_unresolved", "ABA_FALSE_RECEIPT")
        with (
            patch.object(GitWriter, "launch", side_effect=AssertionError("REDISPATCH")),
            self.assertRaises(GitPublishUncertainError),
        ):
            self.publish(staged)
        self.assertEqual(self.tip(), current)

    def test_installed_fence_error_prevents_commit_and_any_later_dispatch(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        original = self.store.put

        def put(intent, name, value, **kwargs):
            result = original(intent, name, value, **kwargs)
            if name == "attempt.json":
                raise OSError("synthetic fence durability uncertainty")
            return result

        with (
            patch.object(self.store, "put", side_effect=put),
            self.assertRaises(GitPublishUncertainError),
        ):
            self.publish(staged)
        self.assertEqual(self.tip(), current, "COMMIT_SENT_BEFORE_DURABLE_FENCE")
        self.assertTrue(self.store.exists(prepared.intent_id, "attempt.json"))
        with self.assertRaises(GitPublishUncertainError):
            self.publish(staged)
        self.assertEqual(self.recover(staged)["status"], "publication_unresolved")

    def test_saved_generated_objects_restore_without_private_key_or_resigning(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        value = staged.to_dict()
        for item in value["objects"] + [{"oid": value["commit_oid"]}]:
            path = self.repo / ".git/objects" / item["oid"][:2] / item["oid"][2:]
            if path.exists():
                path.unlink()
        os.unlink(self.key["private_key_file"])
        with patch("yamora.gitops.git_apply.private_key", side_effect=AssertionError("RESIGNED")):
            result = self.publish(staged)
        self.assertEqual(result["status"], "git_published")

    def test_corrupt_real_signature_with_rehashed_envelope_never_publishes(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        value = staged.to_dict()
        raw = base64.b64decode(value["commit_source_b64"])
        start = raw.index(b"-----BEGIN SSH SIGNATURE-----\n ") + len(
            b"-----BEGIN SSH SIGNATURE-----\n "
        )
        changed = (
            raw[:start] + (b"A" if raw[start : start + 1] != b"A" else b"B") + raw[start + 1 :]
        )
        value["commit_source_b64"] = base64.b64encode(changed).decode()
        import hashlib

        value["commit_oid"] = hashlib.sha1(
            b"commit " + str(len(changed)).encode() + b"\0" + changed
        ).hexdigest()
        reidentify(value, "staged_id")
        forged = StagedGit.from_dict(
            self.repo,
            value,
            expected_intent_id=prepared.intent_id,
            expected_staged_id=value["staged_id"],
        )
        (self.artifacts / prepared.intent_id / "staged.json").write_bytes(canonical(value) + b"\n")
        commands = []
        original_run = GitWriter.run

        def run(writer, args, **kwargs):
            commands.append(args[0])
            return original_run(writer, args, **kwargs)

        with patch.object(GitWriter, "run", run), self.assertRaises(GitCommandError):
            self.publish(forged)
        self.assertEqual(commands[-1], "verify-commit", "SIGNATURE_NEGATIVE_WRONG_PHASE")
        self.assertEqual(self.tip(), current, "BAD_SIGNATURE_PUBLISHED")
        self.assertFalse(self.store.exists(prepared.intent_id, "attempt.json"))

    def test_empty_git_target_and_pending_db_bypass_signer_and_mutating_git(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 2"}, {"x": b"x: 1"})
        with patch("yamora.gitops.git_apply.GitWriter", side_effect=AssertionError("EMPTY_GIT_IO")):
            staged = stage_git(
                self.repo,
                prepared,
                artifacts=self.store,
                expected_intent_id=prepared.intent_id,
                signer_config=None,
            )
            result = self.publish(staged)
            self.assertEqual(result["status"], "no_git_operations")
            self.assertIsNone(result["receipt"])
            self.assertEqual(result["pending_db"], ["data/people/x.yaml"])
            self.assertEqual(self.recover(staged)["status"], "no_git_operations")
        self.assertFalse(self.store.exists(prepared.intent_id, "attempt.json"))

    def test_wrong_real_key_cannot_publish_or_create_saved_signed_artifact(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        wrong, unused = self.make_key("wrong")
        commands = []
        original_run = GitWriter.run

        def run(writer, args, **kwargs):
            commands.append(args[0])
            return original_run(writer, args, **kwargs)

        with patch.object(GitWriter, "run", run), self.assertRaises(GitCommandError):
            stage_git(
                self.repo,
                prepared,
                artifacts=self.store,
                expected_intent_id=prepared.intent_id,
                signer_config=wrong,
            )
        self.assertEqual(commands[-1], "verify-commit", "SIGNER_NEGATIVE_WRONG_PHASE")
        self.assertEqual(self.tip(), current, "WRONG_SIGNER_PUBLISHED")
        self.assertFalse(self.store.exists(prepared.intent_id, "staged.json"))

    def test_hooks_filters_signer_config_and_environment_cannot_execute(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        marker = self.root / "executed"
        helper = self.root / "hostile-helper"
        helper.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
        helper.chmod(0o755)
        hooks = self.root / "hooks"
        hooks.mkdir()
        (hooks / "reference-transaction").write_text(helper.read_text())
        (hooks / "reference-transaction").chmod(0o755)
        for name, value in (
            ("core.hooksPath", str(hooks)),
            ("core.fsmonitor", str(helper)),
            ("gpg.ssh.program", str(helper)),
            ("gpg.ssh.defaultKeyCommand", str(helper)),
            ("filter.evil.clean", str(helper)),
            ("filter.evil.smudge", str(helper)),
        ):
            self.git("config", name, value)
        (self.repo / ".gitattributes").write_text("*.yaml filter=evil\n")
        prepared = self.prepare(plan, current)
        with patch.dict(
            os.environ,
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath",
                "GIT_CONFIG_VALUE_0": str(hooks),
                "GIT_SSH_COMMAND": str(helper),
                "SSH_ASKPASS": str(helper),
                "SSH_AUTH_SOCK": str(marker),
                "GIT_AUTHOR_NAME": "unexpected owner identity",
            },
        ):
            staged = self.stage(prepared)
            result = self.publish(staged)
        self.assertEqual(result["status"], "git_published")
        self.assertFalse(marker.exists(), "UNTRUSTED_HELPER_EXECUTED")

    def test_receipt_persistence_failure_keeps_one_shot_fence_and_observed_commit(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        original = self.store.put

        def put(intent, name, value, **kwargs):
            if name == "receipt.json":
                raise OSError("synthetic receipt fsync failure")
            return original(intent, name, value, **kwargs)

        with (
            patch.object(self.store, "put", side_effect=put),
            self.assertRaises(GitPublishUncertainError),
        ):
            self.publish(staged)
        self.assertEqual(self.tip(), staged.to_dict()["commit_oid"])
        self.assertTrue(self.store.exists(prepared.intent_id, "attempt.json"))
        with self.assertRaises(GitPublishUncertainError):
            self.publish(staged)
        self.assertEqual(self.recover(staged)["status"], "publication_observed")

    def test_cli_prepare_stage_apply_recover_and_one_shot_refusal(self):
        import json
        import subprocess
        import sys
        from pathlib import Path

        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        for name, value in (
            ("plan", plan),
            ("metadata", META),
            ("public", self.public),
            ("config", self.key),
        ):
            (self.root / (name + ".json")).write_bytes(canonical(value))
            (self.root / (name + ".json")).chmod(0o600)

        def cli(command, *args, expected=0):
            call = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "yamora.gitops",
                    command,
                    "--repo",
                    str(self.repo),
                    "--artifacts",
                    str(self.artifacts),
                    *args,
                ],
                cwd=Path(__file__).resolve().parents[3],
                env=self.env,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(call.returncode, expected, call.stderr.decode())
            self.assertNotIn(self.key["private_key_file"].encode(), call.stdout + call.stderr)
            return json.loads(call.stdout) if call.stdout else None

        reviewed = cli(
            "prepare-git",
            "--plan-file",
            str(self.root / "plan.json"),
            "--expected-plan-id",
            plan["plan_id"],
            "--target-ref",
            TARGET,
            "--expected-old-commit",
            current,
            "--operation-id",
            "1" * 32,
            "--commit-metadata-file",
            str(self.root / "metadata.json"),
            "--signer-policy-file",
            str(self.root / "public.json"),
        )
        self.assertEqual(reviewed["intent_id"], prepared.intent_id)
        staged = cli(
            "stage-git",
            "--expected-intent-id",
            reviewed["intent_id"],
            "--signer-config-file",
            str(self.root / "config.json"),
        )
        arguments = (
            "--expected-intent-id",
            staged["intent_id"],
            "--expected-staged-id",
            staged["staged_id"],
        )
        result = cli("apply-git", *arguments)
        self.assertEqual(result["status"], "git_published")
        self.assertEqual(cli("recover-git", *arguments)["status"], "publication_recorded")
        self.assertEqual(
            cli("apply-git", *arguments, expected=3)["status"], "publication_unresolved"
        )

    def test_empty_trees_gitlinks_and_empty_blob_remain_exact_states(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b""})
        empty = self.git("mktree", "-z", data=b"").stdout.strip()
        root_tree = self.git("rev-parse", current + "^{tree}").stdout.strip().decode()
        rows = self.git("ls-tree", "-z", root_tree).stdout
        rows += b"040000 tree " + empty + b"\tempty\0"
        rows += b"160000 commit " + current.encode() + b"\tsubmodule\0"
        tree = self.git("mktree", "-z", data=rows).stdout.strip().decode()
        selected = (
            self.git("commit-tree", tree, "-p", current, data=b"unmapped tree fixture\n")
            .stdout.strip()
            .decode()
        )
        self.git("update-ref", TARGET, selected, current)
        new_plan = build_plan(
            self.repo,
            plan["preconditions"]["git"]["baseline_commit"],
            selected,
            exported({"x": b""}),
            MAP,
        )
        staged = self.stage(self.prepare(new_plan, selected))
        result = self.publish(staged)
        for name in ("empty", "submodule"):
            self.assertEqual(
                self.git("ls-tree", selected, "--", name).stdout,
                self.git("ls-tree", result["new_commit"], "--", name).stdout,
                "UNMAPPED_TREE_FIDELITY",
            )
        self.assertEqual(self.git("show", result["new_commit"] + ":data/people/x.yaml").stdout, b"")
        self.assertEqual(
            self.git("cat-file", "-e", result["new_commit"] + ":data/people/x.yaml").returncode, 0
        )

    def test_sha256_object_format_real_signing_and_cas(self):
        self.repo = self.root / "sha256-repo"
        self.repo.mkdir()
        self.git("init", "-q", "--object-format=sha256")
        self.git("symbolic-ref", "HEAD", "refs/heads/fixture")
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        self.assertEqual(len(current), 64)
        result = self.publish(self.stage(prepared))
        self.assertEqual(len(result["new_commit"]), 64)
        self.assertEqual(self.tip(), result["new_commit"])

    def test_git_change_count_128_and_129_is_not_chunked(self):
        old = {f"d-{i:03}": b"x: 1" for i in range(128)}
        new = dict.fromkeys(old, b"x: 2")
        prepared, plan, current = self.intent(old, old, new)
        result = self.publish(self.stage(prepared))
        self.assertEqual(result["operation_count"], 128)
        self.assertEqual(
            self.git("rev-parse", result["new_commit"] + "^").stdout.strip().decode(), current
        )
        old["d-128"] = b"x: 1"
        new["d-128"] = b"x: 2"
        with self.assertRaisesRegex(PlanError, "128"):
            self.intent(old, old, new)

    def test_contradictory_saved_summary_and_receipt_cannot_be_accepted(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        self.publish(staged)
        path = self.artifacts / prepared.intent_id / "intent.json"
        broken = prepared.to_dict()
        broken["plan"]["summary"]["update"] = True
        path.write_bytes(canonical(broken) + b"\n")
        with self.assertRaisesRegex(PlanError, "saved intent"):
            self.recover(staged)
        path.write_bytes(canonical(prepared.to_dict()) + b"\n")
        path = self.artifacts / prepared.intent_id / "receipt.json"
        broken = self.store.read(prepared.intent_id, "receipt.json")
        broken["operation_count"] = True
        path.write_bytes(canonical(broken) + b"\n")
        with self.assertRaisesRegex(PlanError, "contradicts"):
            self.recover(staged)

    def test_empty_cli_does_not_read_signer_configuration(self):
        import json
        import subprocess
        import sys
        from pathlib import Path

        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 2"}, {"x": b"x: 1"})
        self.store.put(prepared.intent_id, "intent.json", prepared.to_dict())
        self.store.prepare_lock(prepared.intent_id)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamora.gitops",
                "stage-git",
                "--repo",
                str(self.repo),
                "--artifacts",
                str(self.artifacts),
                "--expected-intent-id",
                prepared.intent_id,
                "--signer-config-file",
                str(self.root / "absent-signing-config.json"),
            ],
            cwd=Path(__file__).resolve().parents[3],
            env=self.env,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(
            result.returncode, 0, "EMPTY_SIGNER_CONFIG_ACCESSED: " + result.stderr.decode()
        )
        self.assertIsNone(json.loads(result.stdout)["commit_oid"])

    def test_signed_artifact_cannot_be_transplanted_to_fresh_store_without_fence(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        clone_root = self.root / "other-artifacts"
        clone_root.mkdir(mode=0o700)
        with GitArtifacts(clone_root) as clone:
            clone.put(prepared.intent_id, "intent.json", prepared.to_dict())
            clone.prepare_lock(prepared.intent_id)
            clone.put(prepared.intent_id, "staged.json", staged.to_dict())
            with self.assertRaisesRegex(PlanError, "artifact store", msg="ARTIFACT_TRANSPLANT"):
                publish_git(
                    self.repo,
                    staged,
                    artifacts=clone,
                    expected_intent_id=prepared.intent_id,
                    expected_staged_id=staged.staged_id,
                )
        self.assertEqual(self.tip(), current)

    def test_preparation_deadline_is_infrastructure_not_behavioral_rejection(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        with self.assertRaises(GitInfrastructureError) as error:
            self.prepare(plan, current, limits=Limits(deadline=0.0000001))
        self.assertNotIsInstance(error.exception, PlanError)
        self.assertEqual(self.tip(), current)

    def test_native_prepared_lock_excludes_symbolic_writer_until_commit(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        original = _Child.expect
        witnessed = []

        def expect(child, acknowledgment):
            original(child, acknowledgment)
            if acknowledgment == b"prepare: ok\n":
                competing = self.git("symbolic-ref", TARGET, "refs/heads/fixture", check=False)
                self.assertNotEqual(competing.returncode, 0, "PREPARED_REF_LOCK_NOT_EXCLUSIVE")
                self.assertIn(b"lock", competing.stderr)
                self.assertEqual(self.tip(), current, "PREPARE_PUBLISHED_EARLY")
                witnessed.append(True)

        with patch.object(_Child, "expect", expect):
            result = self.publish(staged)
        self.assertEqual(witnessed, [True], "NATIVE_PREPARE_WITNESS")
        self.assertEqual(self.tip(), result["new_commit"])

    def test_sigint_after_native_prepare_aborts_on_eof_without_fence(self):
        import signal

        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        original = _Child.expect
        children = []

        def expect(child, acknowledgment):
            original(child, acknowledgment)
            if acknowledgment == b"prepare: ok\n":
                children.append(child.process.pid)
                os.kill(os.getpid(), signal.SIGINT)

        with patch.object(_Child, "expect", expect), self.assertRaises(KeyboardInterrupt):
            self.publish(staged)
        self.assertEqual(self.tip(), current, "CANCELLED_PREPARE_PUBLISHED")
        self.assertFalse(
            (self.repo / ".git" / (TARGET + ".lock")).exists(), "CANCELLED_PREPARE_LOCK_RETAINED"
        )
        self.assertFalse(self.store.exists(prepared.intent_id, "attempt.json"))
        self.assertEqual(len(children), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0], 0)

    def test_explicit_timestamp_edges_and_unicode_identity_are_exact(self):
        for timestamp in (0, 4102444800):
            prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
            meta = META | {
                "timestamp": timestamp,
                "author": {"name": "Synthetic Café", "email": "author@example.invalid"},
            }
            prepared = prepare_git(
                self.repo,
                plan,
                expected_plan_id=plan["plan_id"],
                target_ref=TARGET,
                expected_old_commit=current,
                operation_id="1" * 32,
                commit_metadata=meta,
                signer_policy=self.public,
            )
            result = self.publish(self.stage(prepared))
            raw = self.git("cat-file", "commit", result["new_commit"]).stdout
            self.assertIn(
                (
                    "author Synthetic Café <author@example.invalid> " + str(timestamp) + " +0000\n"
                ).encode(),
                raw,
            )

    def test_surviving_receipt_without_attempt_never_redispatches_after_aba(self):
        prepared, plan, current = self.intent({"x": b"x: 1"}, {"x": b"x: 1"}, {"x": b"x: 2"})
        staged = self.stage(prepared)
        self.publish(staged)
        (self.artifacts / prepared.intent_id / "attempt.json").unlink()
        self.git("update-ref", TARGET, current)
        commits = []
        original = _Child.send

        def send(child, data):
            if data == b"commit\0":
                commits.append(data)
            return original(child, data)

        with patch.object(_Child, "send", send):
            try:
                self.publish(staged)
            except GitPublishUncertainError:
                pass
        self.assertEqual(commits, [], "STORED_STATUS_ALLOWED_REDISPATCH")
        self.assertEqual(self.tip(), current, "STORED_STATUS_MOVED_REF")
