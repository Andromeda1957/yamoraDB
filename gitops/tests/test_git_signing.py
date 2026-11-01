"""Synthetic Git/key fixtures and public signer/identity boundary tests."""

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from yamora.gitops.git_writer import GitInfrastructureError
from yamora.gitops.git_writer import GitWriter
from yamora.gitops.model import Limits
from yamora.gitops.model import PlanError
from yamora.gitops.signing import allowed_signers
from yamora.gitops.signing import metadata
from yamora.gitops.signing import policy
from yamora.gitops.signing import private_key

TARGET = "refs/yamora-gitops/targets/fixture"
META = {
    "author": {"name": "Synthetic Author", "email": "author@example.invalid"},
    "committer": {"name": "Synthetic Publisher", "email": "publisher@example.invalid"},
    "timestamp": 1700000000,
    "timezone": "+0000",
    "message": "Synthetic GitOps update",
}


class SyntheticGit:
    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.env = {
            "PATH": os.defpath,
            "HOME": str(self.root),
            "LC_ALL": "C",
            "TMPDIR": str(self.root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Synthetic Author",
            "GIT_AUTHOR_EMAIL": "author@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic Publisher",
            "GIT_COMMITTER_EMAIL": "publisher@example.invalid",
        }
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("symbolic-ref", "HEAD", "refs/heads/fixture")
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)

    def git(self, *args, data=None, check=True):
        return subprocess.run(
            [
                shutil.which("git", path=os.defpath),
                "--no-pager",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "gc.auto=0",
                *args,
            ],
            cwd=self.repo,
            env=self.env,
            input=data,
            capture_output=True,
            check=check,
            timeout=10,
        )

    def commit(self, documents):
        directory = self.repo / "data/people"
        directory.mkdir(parents=True, exist_ok=True)
        for p in directory.glob("*.yaml"):
            p.unlink()
        for name, value in documents.items():
            (directory / (name + ".yaml")).write_bytes(value)
        self.git("add", "--all")
        self.git("commit", "-q", "--allow-empty", "-m", "synthetic fixture")
        return self.git("rev-parse", "HEAD").stdout.strip().decode("ascii")

    def exact(self, people, *, keep=b"sibling bytes\n"):
        """Commit an exact tree: None omits data/people and {} records an empty tree."""

        def blob(source):
            return self.git("hash-object", "-w", "--stdin", data=source).stdout.strip()

        def blobs(sources):
            # One Git process writes every exact blob of a large tree.
            folder = Path(tempfile.mkdtemp(dir=self.root))
            paths = []
            for number, source in enumerate(sources):
                paths.append(folder / str(number))
                paths[-1].write_bytes(source)
            data = b"".join(bytes(path) + b"\n" for path in paths)
            return self.git(
                "hash-object", "-w", "--no-filters", "--stdin-paths", data=data
            ).stdout.split()

        def mktree(rows):
            return self.git("mktree", "-z", data=b"".join(rows)).stdout.strip()

        data = [b"100644 blob " + blob(keep) + b"\tkeep.txt\0"]
        if people is not None:
            names = sorted(people)
            rows = [
                b"100644 blob " + oid + b"\t" + name.encode() + b".yaml\0"
                for name, oid in zip(names, blobs([people[n] for n in names]), strict=True)
            ]
            data.append(b"040000 tree " + mktree(rows) + b"\tpeople\0")
        root = mktree(
            [
                b"100644 blob " + blob(b"# unrelated\n") + b"\tREADME.md\0",
                b"040000 tree " + mktree(data) + b"\tdata\0",
            ]
        )
        commit = self.git("commit-tree", root.decode("ascii"), "-m", "synthetic exact tree")
        return commit.stdout.strip().decode("ascii")

    def listing(self, commit):
        rows = self.git("ls-tree", "-r", "-t", "-z", "--full-tree", commit).stdout.split(b"\0")
        result = {}
        for row in rows[:-1]:
            metadata, path = row.split(b"\t", 1)
            mode, _, oid = metadata.decode("ascii").split(" ")
            result[path.decode("ascii")] = (mode, oid)
        return result

    def make_key(self, name="signer"):
        executable = shutil.which("ssh-keygen", path=os.defpath)
        if executable is None:
            raise GitInfrastructureError("managed optional ssh-keygen prerequisite missing")
        key = self.root / name
        subprocess.run(
            [
                executable,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "synthetic-fixture",
                "-f",
                str(key),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=10,
            env=self.env,
            start_new_session=True,
        )
        record = " ".join(key.with_suffix(".pub").read_text().split()[:2])
        blob = base64.b64decode(record.split()[1])
        public = {
            "backend": "ssh-ed25519-v1",
            "principal": "fixture@example.invalid",
            "public_key": record,
            "fingerprint": "SHA256:"
            + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="),
        }
        return {"private_key_file": str(key)}, public

    def writer(self, public=None):
        return GitWriter(
            self.repo,
            Limits(),
            time.monotonic() + 60,
            public_policy=allowed_signers(public) if public else None,
        )


class GitSigningTests(SyntheticGit, unittest.TestCase):
    def test_public_policy_rejects_injected_identity_and_key_records(self):
        config, public = self.make_key()
        self.assertEqual(policy(public), public)
        for changed in (
            {"principal": "fixture,*"},
            {"principal": "fixture\ncommand"},
            {"public_key": public["public_key"] + " comment"},
            {"fingerprint": "SHA256:" + "a" * 43},
            {"backend": "arbitrary-program"},
        ):
            with self.subTest(changed=changed), self.assertRaises(PlanError):
                policy(public | changed)

    def test_commit_identity_timestamp_and_unknown_fields_reject(self):
        self.assertEqual(metadata(META), META)
        for changed in (
            {"timestamp": True},
            {"timestamp": "1700000000"},
            {"timezone": "+0100"},
            {"author": {"name": "Synthetic\ncommitter evil", "email": "x@y"}},
            {"committer": {"name": "Synthetic", "email": "x@y -S"}},
            {"message": "message\x00injection"},
            {"extra": "not allowed"},
        ):
            with self.subTest(changed=changed), self.assertRaises(PlanError):
                metadata(META | changed)

    def test_private_key_is_pinned_and_never_copied_into_workspace(self):
        config, public = self.make_key()
        with self.writer(public) as writer:
            with private_key(config, writer) as pinned:
                self.assertEqual(
                    Path(pinned).stat().st_ino, Path(config["private_key_file"]).stat().st_ino
                )
                self.assertEqual(
                    sorted(p.name for p in writer.work.iterdir()),
                    ["allowed-signers", "config", "home", "revocations", "tmp"],
                )
            original = Path(config["private_key_file"])
            original.chmod(0o644)
            with self.assertRaisesRegex(PlanError, "protection"):
                with private_key(config, writer):
                    self.fail("UNPROTECTED_KEY")
            original.chmod(0o600)
            link = self.root / "key-link"
            link.symlink_to(original)
            with self.assertRaisesRegex(PlanError, "symlink"):
                with private_key({"private_key_file": str(link)}, writer):
                    self.fail("SYMLINKED_KEY")
