"""Behavioral proof with real Git objects and native HTTP reads."""

import base64
import itertools
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.client import YamlDBClient
from yamora.gitops import Export
from yamora.gitops import Limits
from yamora.gitops import Mapping
from yamora.gitops import PlanError
from yamora.gitops import build_plan
from yamora.gitops import capture_export
from yamora.gitops.git_reader import GitReader
from yamora.gitops.model import canonical
from yamora.gitops.model import digest
from yamora.gitops.model import etag
from yamora.gitops.model import mappings_checked
from yamora.gitops.model import strict_json

ROOT = Path(__file__).resolve().parents[3]
MAP = [Mapping("people", "data/people")]
REV = "1234567890abcdef"


def exported(documents, *, revision=REV):
    return Export.from_dict(
        {
            "format": "yamora-gitops-export-v1",
            "revision": revision,
            "revision_scheme": "xor-fnv-v2",
            "scope": ["people"],
            "collections": ["people"],
            "documents": [
                {
                    "collection": "people",
                    "document": key,
                    "etag": etag(value),
                    "source_b64": base64.b64encode(value).decode(),
                }
                for key, value in sorted(documents.items())
            ],
        }
    )


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "user.name", "GitOps test")

    def git(self, *args, input=None):
        return (
            subprocess.check_output(
                ["/usr/bin/git", *args],
                cwd=self.repo,
                input=input,
                stderr=subprocess.PIPE,
                timeout=5,
                env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
            )
            .decode()
            .strip()
        )

    def own_child(self, child):
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()

        self.addCleanup(cleanup)
        return child

    def commit(self, documents):
        directory = self.repo / "data/people"
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        for key, value in documents.items():
            (directory / (key + ".yaml")).write_bytes(value)
        self.git("add", "--all")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def plan(self, base, current, db, **kwargs):
        return build_plan(self.repo, base, current, exported(db), MAP, **kwargs)


class PlannerTests(GitFixture):
    def test_three_way_state_matrix_and_missing_versus_empty(self):
        values = [None, b"", b"a: 1\n", b"a: 2\n"]
        combinations = list(itertools.product(values, repeat=3))
        baseline, current, db = {}, {}, {}
        for index, triple in enumerate(combinations):
            for records, value in zip((baseline, current, db), triple, strict=True):
                if value is not None:
                    records[f"doc-{index:03d}"] = value
        base = self.commit(baseline)
        selected = self.commit(current)
        plan = self.plan(base, selected, db)
        entries = {entry["document"]: entry for entry in plan["entries"]}
        self.assertNotIn("doc-000", entries)
        for index, (b, g, d) in enumerate(combinations[1:], 1):
            with self.subTest(b=b, g=g, d=d):
                entry = entries[f"doc-{index:03d}"]
                for state, source in (("baseline", b), ("git", g), ("db", d)):
                    self.assertEqual(entry[state]["present"], source is not None)
                    if source is not None:
                        self.assertEqual(base64.b64decode(entry[state]["source_b64"]), source)
                if g == d:
                    self.assertEqual(entry["status"], "unchanged" if g == b else "converged")
                    self.assertEqual(entry["target"], "none")
                elif g != b and d != b:
                    self.assertEqual((entry["status"], entry["target"]), ("conflict", "none"))
                else:
                    self.assertEqual(entry["target"], "git" if g == b else "db")
                    old, new = (g, d) if g == b else (d, g)
                    self.assertEqual(
                        entry["status"],
                        "delete" if new is None else "add" if old is None else "update",
                    )

    def test_exact_bytes_deterministic_plan_and_cas_preconditions(self):
        old = b"# header\r\nname: 'Alex' # preserve comment\r\n"
        new = b"# edited comment\r\nname: 'Alex' # preserve comment\r\n"
        base = self.commit({"alex": old})
        selected = self.commit({"alex": new, "empty": b""})
        before = self.git("status", "--porcelain")
        plan = self.plan(base, selected, {"alex": old})
        self.assertEqual(plan, self.plan(base, "HEAD", {"alex": old}))
        self.assertEqual(before, self.git("status", "--porcelain"))
        self.assertEqual(
            plan["preconditions"]["git"]["current_tree"],
            self.git("rev-parse", selected + "^{tree}"),
        )
        alex, empty = plan["entries"]
        self.assertEqual(alex["status"], "update")
        self.assertEqual(base64.b64decode(alex["git"]["source_b64"]), new)
        self.assertEqual(alex["preconditions"]["db"]["etag"], etag(old))
        self.assertEqual(
            empty["preconditions"]["db"], {"etag": None, "present": False, "create_only": True}
        )
        self.assertEqual(empty["git"]["bytes"], 0)
        identity = plan.pop("plan_id")
        self.assertEqual(identity, digest(canonical(plan)))
        # Dirty checkout content is outside selected committed input.
        (self.repo / "data/people/alex.yaml").write_bytes(b"dirty")
        self.assertEqual(self.plan(base, selected, {"alex": old})["plan_id"], identity)

    def test_maps_and_selectors_reject_path_and_option_surprises(self):
        base = self.commit({"alex": b"a: 1\n"})
        for ref in (
            "--help",
            "-c",
            "HEAD:data/people",
            "HEAD~1",
            "HEAD^{tree}",
            "@{0}",
            "refs/heads/../main",
            "refs/heads/x;touch",
            "$(touch marker)",
        ):
            with self.subTest(ref=ref), self.assertRaises(PlanError):
                self.plan(base, ref, {})
        for prefix in ("../data", "/data", "data//x", ".git", "data/..", "data/x.yaml", "data\\x"):
            with self.subTest(prefix=prefix), self.assertRaises(PlanError):
                Mapping("people", prefix)
        with self.assertRaises(PlanError):
            build_plan(self.repo, base, base, exported({}), MAP + [Mapping("other", "data")])

    def test_reject_symlink_submodule_executable_and_nested_mapping_entries(self):
        base = self.commit({"alex": b"a: 1\n"})
        original_tree = self.git("rev-parse", base + "^{tree}")
        blob = self.git("hash-object", "-w", "--stdin", input=b"outside")
        for mode, oid, path in (
            ("120000", blob, "data/people/link.yaml"),
            ("160000", base, "data/people/sub"),
            ("100755", blob, "data/people/executable.yaml"),
            ("100644", blob, "data/people/nested/doc.yaml"),
            ("120000", blob, "data"),
            ("100644", blob, "data/people/doc.yml"),
        ):
            self.git("read-tree", original_tree)
            if path == "data":
                self.git("read-tree", "--empty")
            self.git("update-index", "--add", "--cacheinfo", mode, oid, path)
            tree = self.git("write-tree")
            with self.subTest(mode=mode, path=path), self.assertRaises(PlanError):
                self.plan(base, tree, {})

    def test_hooks_filters_and_git_environment_are_not_executed(self):
        base = self.commit({"alex": b"x: 1\r\n"})
        marker = self.root / "executed"
        hook = self.repo / ".git/hooks/post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        self.git("config", "core.fsmonitor", str(hook))
        self.git("config", "filter.evil.smudge", str(hook))
        (self.repo / ".gitattributes").write_text("*.yaml filter=evil\n")
        with patch.dict(
            os.environ,
            {
                "GIT_EXTERNAL_DIFF": str(hook),
                "GIT_DIR": "/absent",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "alias.cat-file",
                "GIT_CONFIG_VALUE_0": "!touch marker",
            },
        ):
            self.assertEqual(
                self.plan(base, base, {"alex": b"x: 1\r\n"})["summary"]["unchanged"], 1
            )
        self.assertFalse(marker.exists())

    def test_snapshot_reads_any_number_of_blobs_with_two_git_processes(self):
        documents = {f"doc-{n:04}": b"# exact\r\nn: %d\r\n" % n for n in range(600)}
        documents.update({"copy": documents["doc-0000"], "empty": b""})
        base = self.commit(documents)
        started = []
        real = subprocess.Popen

        def counted(*args, **kwargs):
            started.append(args[0])
            return real(*args, **kwargs)

        with patch("yamora.gitops.git_reader.subprocess.Popen", side_effect=counted):
            loaded, trees = GitReader(self.repo, Limits()).snapshot(base, MAP)
            self.assertEqual(len(started), 2, "PROCESS_COUNT_MUST_NOT_GROW_WITH_DOCUMENTS")
            # Every size limit holds from the listing, before any blob is read.
            with self.assertRaisesRegex(PlanError, "bytes exceed"):
                GitReader(self.repo, Limits(max_total_bytes=4096)).snapshot(base, MAP)
            self.assertEqual(len(started), 3)
        self.assertEqual({key[1]: value[0] for key, value in loaded.items()}, documents)
        for name in ("doc-0599", "copy", "empty"):
            self.assertEqual(
                loaded[("people", name)][1],
                self.git("rev-parse", f"{base}:data/people/{name}.yaml"),
            )
        self.assertEqual(trees, {"people": self.git("rev-parse", f"{base}:data/people")})

    def test_limits_and_symlinked_repo(self):
        base = self.commit({"one": b"x" * 40, "two": b"y"})
        for limits in (
            Limits(max_documents=1),
            Limits(max_document_bytes=8),
            Limits(max_total_bytes=50),
            Limits(max_tree_entries=1),
            Limits(deadline=0.000001),
        ):
            with self.subTest(limits=limits), self.assertRaises(PlanError):
                self.plan(base, base, {}, limits=limits)
        link = self.root / "link"
        link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(PlanError):
            build_plan(link, base, base, exported({}), MAP)
        reader = GitReader(self.repo, Limits())
        with self.assertRaises(PlanError):
            reader._run(["ls-tree", "-r", "-t", "-l", "-z", "--full-tree", base], 1)
        reader = GitReader(self.repo, Limits(git_timeout=0.000001))
        with self.assertRaises(PlanError):
            reader._run(["ls-tree", "-r", "-t", "-l", "-z", "--full-tree", base], 10000)

    def test_private_runner_rejects_mutation_and_reaps_constructor_handoff_interrupt(self):
        base = self.commit({"alex": b"x: 1\n"})
        reader = GitReader(self.repo, Limits())
        blob = self.git("rev-parse", base + ":data/people/alex.yaml")
        for command, data in (
            (["fetch", "origin"], None),
            (["checkout", "HEAD"], None),
            (["cat-file", "--filters", base], None),
            (["rev-parse", "--help"], None),
            (["cat-file", "--batch"], None),
            (["cat-file", "--batch"], b""),
            (["cat-file", "--batch"], blob.encode()),
            (["cat-file", "--batch"], f"{blob} --textconv\n".encode()),
            (["cat-file", "--batch-all-objects", "--batch"], f"{blob}\n".encode()),
            (["cat-file", "blob", blob], None),
            (["ls-tree", "-r", "-t", "-l", "-z", "--full-tree", base], f"{blob}\n".encode()),
        ):
            with self.subTest(command=command, data=data), self.assertRaises(PlanError):
                reader._run(command, 1000, data=data)
        real_popen = subprocess.Popen
        children = []

        def interrupt_handoff(*args, **kwargs):
            child = self.own_child(real_popen(*args, **kwargs))
            children.append(child)
            signal.raise_signal(signal.SIGINT)
            return child

        with (
            patch("yamora.gitops.git_reader.subprocess.Popen", side_effect=interrupt_handoff),
            self.assertRaises(KeyboardInterrupt),
        ):
            reader.resolve(base, "tree")
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    def test_read_interruption_reaps_owned_child(self):
        base = self.commit({"alex": b"x: 1\n"})
        children = []
        real_popen = subprocess.Popen

        def started(*args, **kwargs):
            child = self.own_child(real_popen(*args, **kwargs))
            children.append(child)
            return child

        with (
            patch("yamora.gitops.git_reader.subprocess.Popen", side_effect=started),
            patch(
                "yamora.gitops.git_reader.selectors.DefaultSelector.select",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            GitReader(self.repo, Limits()).resolve(base, "tree")
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    def test_missing_promisor_object_never_invokes_transport_helper(self):
        base = self.commit({})
        missing = "1" * 40
        self.git(
            "update-index", "--add", "--cacheinfo", "100644", missing, "data/people/missing.yaml"
        )
        tree = self.git("write-tree", "--missing-ok")
        marker = self.root / "transport-ran"
        self.git("config", "extensions.partialClone", "origin")
        self.git("config", "remote.origin.promisor", "true")
        self.git("config", "remote.origin.url", f"ext::touch {marker}")
        with self.assertRaises(PlanError):
            self.plan(base, tree, {})
        self.assertFalse(marker.exists())

    def test_empty_and_absent_collection_metadata_and_scope_are_preserved(self):
        base = self.commit({})
        empty = exported({}).to_dict()
        absent = {**empty, "collections": []}
        plan = build_plan(self.repo, base, base, absent, MAP)
        self.assertEqual(plan["preconditions"]["db"]["collections"], [])
        self.assertEqual(plan["entries"], [])
        other = build_plan(self.repo, base, base, empty, MAP)
        self.assertEqual(other["preconditions"]["db"]["collections"], ["people"])
        self.assertNotEqual(other["plan_id"], plan["plan_id"])
        with self.assertRaises(PlanError):
            build_plan(self.repo, base, base, empty, [Mapping("other", "data/other")])

    def test_sha256_git_objects_and_explicit_plain_ref(self):
        self.repo = self.root / "sha256"
        self.repo.mkdir()
        self.git("init", "-q", "--object-format=sha256")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "user.name", "GitOps test")
        base = self.commit({"alex": b"x: 1\n"})
        self.git("branch", "selected")
        self.assertEqual(len(base), 64)
        self.assertEqual(
            self.plan(base, "refs/heads/selected", {"alex": b"x: 1\n"})["summary"]["unchanged"], 1
        )

    def test_cli_offline_exit_codes_and_source_preservation(self):
        base = self.commit({"alex": b"a: 1\n"})
        selected = self.commit({"alex": b"a: 2\n"})
        export = self.root / "export.json"
        export.write_bytes(canonical(exported({"alex": b"a: 3\n"}).to_dict()))
        args = [
            sys.executable,
            "-m",
            "yamora.gitops",
            "plan",
            "--repo",
            str(self.repo),
            "--baseline",
            base,
            "--current",
            selected,
            "--map",
            "people=data/people",
            "--export-file",
            str(export),
        ]
        result = subprocess.run(args, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"]["conflict"], 1)
        export.write_bytes(canonical(exported({"alex": b"a: 1\n"}).to_dict()))
        result = subprocess.run(args, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["entries"][0]["target"], "db")
        args[args.index("--current") + 1] = "HEAD:data"
        result = subprocess.run(args, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")


class ExportTests(unittest.TestCase):
    def test_overlapping_prefix_rejects_even_with_intervening_sibling(self):
        with self.assertRaises(PlanError):
            mappings_checked(
                [
                    Mapping("one", "data"),
                    Mapping("two", "data-sibling"),
                    Mapping("three", "data/nested"),
                ]
            )

    def test_export_validates_exact_bytes_etags_completeness_and_limits(self):
        good = exported({"alex": b"# note\nname: 'Alex'\n", "empty": b""}).to_dict()
        self.assertEqual(Export.from_dict(good).to_dict(), good)
        bads = []
        for field, value in (("etag", "0" * 16), ("source_b64", "???"), ("document", "../x")):
            bad = json.loads(json.dumps(good))
            bad["documents"][0][field] = value
            bads.append(bad)
        bad = json.loads(json.dumps(good))
        bad["documents"].append(bad["documents"][0])
        bads.append(bad)
        bad = json.loads(json.dumps(good))
        bad["collections"] = []
        bads.append(bad)
        bad = json.loads(json.dumps(good))
        bad["scope"] = []
        bads.append(bad)
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(PlanError):
                Export.from_dict(bad)
        with self.assertRaises(PlanError):
            Export.from_dict(good, Limits(max_total_bytes=1))
        with self.assertRaises(PlanError):
            strict_json(b'{"revision":1,"revision":2}')

    def test_capture_rejects_revision_drift_on_page_raw_get_and_final_read(self):
        class Client:
            def __init__(self, drift):
                self.count = 0
                self.drift = drift

            def _request(self, path, **kwargs):
                self.count += 1
                revision = REV if self.count != self.drift else "0" * 16
                headers = {"x-yamldb-revision": revision}
                if path == "/readyz":
                    payload = {"revision": REV, "revision_scheme": "xor-fnv-v2"}
                elif path == "/v1/collections":
                    payload = {"collections": ["people"]}
                elif "?" in path:
                    payload = (
                        {"collection": "people", "documents": ["alex"], "next_after": "alex"}
                        if "after=" not in path
                        else {"collection": "people", "documents": [], "next_after": None}
                    )
                else:
                    return (
                        b"x: 1\n",
                        "application/yaml",
                        {**headers, "etag": '"' + etag(b"x: 1\n") + '"'},
                    )
                return canonical(payload), "application/json", headers

        self.assertEqual(
            capture_export(Client(None), MAP).documents[("people", "alex")].source, b"x: 1\n"
        )
        for drift in range(2, 7):
            with self.subTest(drift=drift), self.assertRaises(PlanError):
                capture_export(Client(drift), MAP)


class NativeTests(GitFixture):
    def test_real_native_export_plan_and_cli_do_not_mutate_db_or_git(self):
        binary = os.environ.get("YAMORA_TEST_BINARY")
        if not binary:
            self.fail("YAMORA_TEST_BINARY must name the built native daemon")
        source = self.root / "source/people"
        source.mkdir(parents=True)
        original = b"# native keeps this comment\r\nname: 'Alex'\r\n"
        (source / "alex.yaml").write_bytes(original)
        data = self.root / "native"
        data.mkdir()
        subprocess.run(
            [
                binary,
                "--data-dir",
                str(data),
                "--init-disk",
                "--import-yaml",
                str(source.parent),
                "--validate-only",
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        process = subprocess.Popen(
            [binary, "--data-dir", str(data), "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def stop():
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=10)

        self.addCleanup(stop)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(10), "native daemon startup deadline")
            line = process.stdout.readline()
        match = re.search(rb"127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line)
        port = int(match[1])
        self.assertNotEqual(port, 8000)
        client = YamlDBClient(port=port)
        before = client.snapshot_revision()
        export = capture_export(client, MAP)
        self.assertEqual(export.revision, before)
        self.assertEqual(export.revision_scheme, "xor-fnv-v2")
        self.assertEqual(export.documents[("people", "alex")].source, original)
        self.assertEqual(export.documents[("people", "alex")].etag, etag(original))
        base = self.commit({"alex": original})
        selected = self.commit({"alex": b"# edited\nname: 'Alex'\n", "new": b"x: 1\n"})
        plan = build_plan(self.repo, base, selected, export, MAP)
        self.assertEqual((plan["summary"]["update"], plan["summary"]["add"]), (1, 1))
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamora.gitops",
                "plan",
                "--repo",
                str(self.repo),
                "--baseline",
                base,
                "--current",
                selected,
                "--map",
                "people=data/people",
                "--port",
                str(port),
            ],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), plan)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamora.gitops",
                "export",
                "--map",
                "people=data/people",
                "--port",
                str(port),
            ],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), export.to_dict())
        self.assertEqual(client.snapshot_revision(), before)
        self.assertEqual(client.get("people", "alex", revision=before), original)
        self.assertEqual(self.git("status", "--porcelain"), "")


def load_tests(loader, tests, pattern):
    # The existing native Makefile entry names this module explicitly. Include
    # the apply suites there; normal discovery already finds their own modules.
    if pattern is None:
        for module in ("yamora.gitops.tests.test_apply", "yamora.gitops.tests.test_apply_cluster"):
            tests.addTests(loader.loadTestsFromName(module))
    return tests


if __name__ == "__main__":
    unittest.main()
