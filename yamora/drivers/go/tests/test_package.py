"""Public Go consumers resolve v0.1.0 from the local artifact, never a replace."""

import importlib.util
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.drivers.python.tests.package_support import command
from yamora.drivers.python.tests.package_support import example_arguments
from yamora.drivers.python.tests.package_support import native

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/Andromeda1957/yamldb/yamora/drivers/go"
FILES = {
    "LICENSE",
    "README.md",
    "VERSION",
    "go.mod",
    "aggregate.go",
    "binary.go",
    "binary_operations.go",
    "binary_reply.go",
    "binary_wire.go",
    "changes.go",
    "client.go",
    "cluster.go",
    "documents.go",
    "index_build.go",
    "replication.go",
    "search.go",
    "stream.go",
    "examples/crud_tls/main.go",
}


class GoPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.go = os.environ.get("YAMORA_PACKAGE_GO") or shutil.which("go")
        if not cls.go:
            raise AssertionError("pinned local Go toolchain required; no download or skip in tests")
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="go-artifact-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.root = Path(cls.allocation.name)
        spec = importlib.util.spec_from_file_location(
            "go_package_builder", ROOT / "build_package.py"
        )
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)
        cls.dist = cls.builder.build(ROOT, cls.root / "dist")
        cls.archive = (
            cls.dist / "proxy/github.com/!andromeda1957/website/yamora/drivers/go/@v/v0.1.0.zip"
        )
        cls.source = cls.root / "source"
        cls.source.mkdir()
        with tarfile.open(cls.dist / "yamora-go-0.1.0.tar.gz") as archive:
            archive.extractall(cls.source, filter="data")
        cls.source = cls.source / "yamora-go-0.1.0"
        cls.environment = {
            **os.environ,
            "GOPROXY": (cls.dist / "proxy").as_uri(),
            "GOSUMDB": "off",
            "GONOPROXY": "none",
            "GONOSUMDB": "*",
            "GOPRIVATE": "",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOENV": "off",
            "GOFLAGS": "-mod=mod -p=2",
            "GOMAXPROCS": "2",
            "GOCACHE": str(cls.root / "build-cache"),
            "GOMODCACHE": str(cls.root / "module-cache"),
            "GOPATH": str(cls.root / "go-home"),
        }

    def test_exact_source_module_contents_license_and_version(self):
        self.assertEqual(
            {str(p.relative_to(self.source)) for p in self.source.rglob("*") if p.is_file()}, FILES
        )
        with zipfile.ZipFile(self.archive) as archive:
            prefix = MODULE + "@v0.1.0/"
            self.assertEqual(set(archive.namelist()), {prefix + name for name in FILES})
            for name in FILES:
                self.assertEqual(archive.read(prefix + name), (self.source / name).read_bytes())
                self.assertEqual(archive.read(prefix + name), (ROOT / name).read_bytes())
        metadata = json.loads(self.archive.with_suffix(".info").read_text())
        self.assertEqual(metadata["Version"], "v0.1.0")
        self.assertEqual((self.source / "VERSION").read_text(), "0.1.0\n")

    def run_native(self, executable):
        allocation = tempfile.TemporaryDirectory(dir=self.root, prefix="native-")
        self.addCleanup(allocation.cleanup)
        with native(Path(allocation.name)) as (ports, certificates, read, write):
            args = example_arguments(ports, certificates, read, write)
            result = command([executable, *args], cwd=self.root, env=self.environment)
            self.assertEqual(result.stdout, "YAMORA_GO_PACKAGE_CRUD_OK\n")
            args[args.index("--ca") + 1] = str(certificates / "foreign.pem")
            rejected = subprocess.run(
                [str(executable), *args],
                cwd=self.root,
                env=self.environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(rejected.stdout, "")
            self.assertEqual(
                rejected.stderr,
                "packaged CRUD failed; preserve uncertain writes for explicit recovery\n",
            )

    def test_private_module_consumer_and_public_tls_crud(self):
        root = self.root / "consumer"
        root.mkdir()
        (root / "go.mod").write_text(
            f"module example.invalid/yamora-package-consumer\n\ngo 1.23\n\nrequire {MODULE} v0.1.0\n"
        )
        shutil.copyfile(self.source / "examples/crud_tls/main.go", root / "main.go")
        executable = root / "crud"
        command(
            [self.go, "build", "-o", executable, "."], cwd=root, env=self.environment, timeout=600
        )
        result = command([self.go, "list", "-m", "-json", MODULE], cwd=root, env=self.environment)
        resolved = json.loads(result.stdout)
        self.assertEqual(resolved["Version"], "v0.1.0")
        self.assertNotIn("Replace", resolved)
        self.assertTrue(
            Path(resolved["Dir"])
            .resolve(strict=True)
            .is_relative_to((self.root / "module-cache").resolve(strict=True))
        )
        command([self.go, "mod", "verify"], cwd=root, env=self.environment)
        dependencies = command(
            [self.go, "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "."],
            cwd=root,
            env=self.environment,
        ).stdout.split()
        self.assertEqual(set(dependencies), {"example.invalid/yamora-package-consumer", MODULE})
        self.run_native(executable)

    def test_extracted_source_builds_offline_and_runs_public_tls_crud(self):
        environment = {**self.environment, "GOPROXY": "off"}
        executable = self.root / "source-crud"
        command(
            [self.go, "build", "-o", executable, "./examples/crud_tls"],
            cwd=self.source,
            env=environment,
            timeout=600,
        )
        self.run_native(executable)

    def test_builder_refuses_unlisted_paths_missing_files_and_symlink_inputs(self):
        root = self.root / "bad-source"
        root.mkdir()
        (root / "package-files.txt").write_text("../LICENSE\n")
        with self.assertRaisesRegex(ValueError, "input"):
            self.builder.inputs(root)
        (root / "package-files.txt").write_text("LICENSE\n")
        with self.assertRaises(FileNotFoundError):
            self.builder.inputs(root)
        (root / "LICENSE").symlink_to(ROOT / "LICENSE")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.builder.inputs(root)
        with self.assertRaisesRegex(ValueError, "outside"):
            self.builder.build(ROOT, ROOT / "dist")


if __name__ == "__main__":
    unittest.main()
