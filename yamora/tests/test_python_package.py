"""Actual wheel/sdist consumers; no checkout import path or package substitutes."""

import ast
import contextlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from email.parser import BytesParser
from pathlib import Path
from unittest import mock

from tools.shared.scratch import runtime_root
from yamora.drivers.python.tests.package_support import command
from yamora.drivers.python.tests.package_support import consumer
from yamora.drivers.python.tests.package_support import example_arguments
from yamora.drivers.python.tests.package_support import isolated_env
from yamora.drivers.python.tests.package_support import native

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "drivers/python/build_package.py"
PUBLIC = (
    "__init__",
    "client",
    "cluster_client",
    "http_transport",
    "binary_client",
    "binary_reply",
    "binary_wire",
)
MODULES = PUBLIC + (
    "backup",
    "backup_stream",
    "catalog_data",
    "storage",
    "validation",
    "yamoractl",
    "yamldbctl",
)


class PythonPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="python-artifact-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.root = Path(cls.allocation.name)
        cls.dist = cls.root / "dist"
        command([sys.executable, BUILDER, "--output", cls.dist], cwd=cls.root)
        cls.wheel = cls.dist / "yamora-0.3.0-py3-none-any.whl"
        cls.sdist = cls.dist / "yamora-0.3.0.tar.gz"

    def test_wheel_public_admin_closure_license_metadata_and_example(self):
        with zipfile.ZipFile(self.wheel) as archive:
            names = set(archive.namelist())
            runtime = {f"yamora/{name}.py" for name in MODULES} | {"yamldb/__init__.py"}
            for name in MODULES:
                self.assertEqual(
                    archive.read(f"yamora/{name}.py"), (ROOT / f"{name}.py").read_bytes()
                )
            info = "yamora-0.3.0.dist-info/"
            data = "yamora-0.3.0.data/data/share/doc/yamora/examples/crud_tls.py"
            expected = (
                runtime
                | {data}
                | {
                    info + name
                    for name in (
                        "METADATA",
                        "WHEEL",
                        "entry_points.txt",
                        "top_level.txt",
                        "RECORD",
                        "licenses/LICENSE",
                    )
                }
            )
            self.assertEqual(names, expected)
            self.assertEqual(
                archive.read(info + "licenses/LICENSE"), (ROOT / "LICENSE").read_bytes()
            )
            metadata = BytesParser().parsebytes(archive.read(info + "METADATA"))
            self.assertEqual(metadata["Name"], "yamora")
            self.assertEqual(metadata["Version"], "0.3.0")
            self.assertEqual(metadata["License-Expression"], "MIT")
            self.assertEqual(metadata.get_all("Requires-Dist"), ['PyYAML>=6.0.2; extra == "admin"'])
            scripts = archive.read(info + "entry_points.txt").decode()
            self.assertIn("yamoractl = yamora.yamoractl:main", scripts)
            self.assertIn("yamldbctl = yamora.yamoractl:main", scripts)
            # Actual shipped imports, including relative imports, must close over the artifact.
            for name in PUBLIC:
                tree = ast.parse(archive.read(f"yamora/{name}.py"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.level and node.module:
                        self.assertIn(node.module.split(".")[0], PUBLIC)
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertIn(alias.name.split(".")[0], sys.stdlib_module_names)
            self.assertEqual(
                archive.read(data), (ROOT / "drivers/python/examples/crud_tls.py").read_bytes()
            )

    def test_sdist_rebuilds_independently_with_identical_installed_payload(self):
        destination = self.root / "unpacked"
        destination.mkdir(exist_ok=True)
        with tarfile.open(self.sdist) as archive:
            members = archive.getmembers()
            prefix = "yamora-0.3.0/"
            expected = (
                {f"{name}.py" for name in MODULES}
                | {
                    "compat/__init__.py",
                    "LICENSE",
                    "README.md",
                    "pyproject.toml",
                    "PKG-INFO",
                    "setup.cfg",
                    "drivers/python/examples/crud_tls.py",
                }
                | {
                    "yamora.egg-info/" + name
                    for name in (
                        "PKG-INFO",
                        "SOURCES.txt",
                        "dependency_links.txt",
                        "entry_points.txt",
                        "requires.txt",
                        "top_level.txt",
                    )
                }
            )
            self.assertEqual(
                {member.name.removeprefix(prefix) for member in members if member.isfile()},
                expected,
            )
            self.assertTrue(all(member.isdir() or member.isfile() for member in members))
            archive.extractall(destination, filter="data")
        source = destination / "yamora-0.3.0"
        rebuilt = self.root / "rebuilt"
        rebuilt.mkdir()
        command(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys; from setuptools import build_meta; build_meta.build_wheel(sys.argv[1])",
                rebuilt,
            ],
            cwd=source,
            env=isolated_env(),
        )
        with (
            zipfile.ZipFile(self.wheel) as original,
            zipfile.ZipFile(next(rebuilt.glob("*.whl"))) as again,
        ):
            self.assertEqual(set(original.namelist()), set(again.namelist()))
            for name in original.namelist():
                if not name.endswith("/RECORD"):
                    self.assertEqual(original.read(name), again.read(name), name)
        python = consumer(self.root / "rebuilt-consumer", next(rebuilt.glob("*.whl")))
        self.check_consumer(python)
        self.run_example(python)

    def check_consumer(self, python):
        program = """
import importlib, importlib.metadata, importlib.util, pathlib, sys
import yamora, yamldb, yamldb.client
from yamora.binary_client import BinaryClient, BinaryConfig
from yamora.binary_reply import BinaryResponse
from yamora import YamoraClusterClient
assert yamldb.client.YamoraClient is yamora.YamoraClient
assert importlib.metadata.version("yamora") == "0.3.0"
assert importlib.util.find_spec("yaml") is None
for name in ("yamora", "yamora.client", "yamora.cluster_client", "yamora.http_transport",
             "yamora.binary_client", "yamora.binary_reply", "yamora.binary_wire", "yamldb"):
    module = importlib.import_module(name)
    assert pathlib.Path(module.__file__).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve())
assert importlib.util.find_spec("yamora.gitops") is None
assert importlib.util.find_spec("yamora.tests") is None
print("PYTHON_ARTIFACT_IMPORTS_OK")
"""
        result = command([python, "-I", "-c", program], cwd=python.parents[1], env=isolated_env())
        self.assertEqual(result.stdout, "PYTHON_ARTIFACT_IMPORTS_OK\n")

    def run_example(self, python):
        root = Path(tempfile.mkdtemp(dir=self.root, prefix="native-"))
        self.addCleanup(shutil.rmtree, root)
        example = python.parents[1] / "share/doc/yamora/examples/crud_tls.py"
        with native(root) as (ports, certificates, read, write):
            args = example_arguments(ports, certificates, read, write)
            result = command(
                [python, "-I", example, *args], cwd=python.parents[1], env=isolated_env()
            )
            self.assertEqual(result.stdout, "YAMORA_PYTHON_PACKAGE_CRUD_OK\n")
            args[args.index("--ca") + 1] = str(certificates / "foreign.pem")
            failed = subprocess.run(
                [str(python), "-I", str(example), *args],
                cwd=python.parents[1],
                env=isolated_env(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(
                failed.stderr,
                "packaged CRUD failed; preserve uncertain writes for explicit recovery\n",
            )
            self.assertEqual(failed.stdout, "")

    def test_wheel_installed_public_tls_crud_without_checkout_or_yaml_dependency(self):
        python = consumer(self.root / "wheel-consumer", self.wheel)
        self.check_consumer(python)
        self.run_example(python)

    def test_installed_raw_operations_pagination_mutations_and_complete_feed(self):
        python = consumer(self.root / "operation-consumer", self.wheel)
        self.check_consumer(python)
        root = Path(tempfile.mkdtemp(dir=self.root, prefix="native-operations-"))
        self.addCleanup(shutil.rmtree, root)
        program = r"""
import importlib.util, json, pathlib, sys
from yamora.binary_client import BinaryClient, BinaryConfig
assert callable(getattr(BinaryClient, "operation", None)), "INSTALLED_OPERATION_API_MISSING"
assert callable(getattr(BinaryClient, "feed", None)), "INSTALLED_FEED_API_MISSING"
assert importlib.util.find_spec("yaml") is None
port, certs, read_path, write_path = sys.argv[1:]
certs = pathlib.Path(certs)
config = BinaryConfig("127.0.0.1", int(port), "localhost", (certs / "ca.pem").read_bytes(),
                      (certs / "client.pem").read_bytes(), (certs / "client.key").read_bytes(),
                      timeout=5, max_frame=4096)
read, write = pathlib.Path(read_path).read_text(), pathlib.Path(write_path).read_text()
source = b"# package raw source\r\nvalue: 1\r\nwide: 9223372036854775807\r\n"
with BinaryClient(config) as client:
    for document in ("one", "two"):
        client.put("packaged-ops", document, source, token=write)
    first = client.operation("POST", "/v1/query/packaged-ops", source=b'{"limit":1}',
                             content_type="application/json", token=read)
    assert b"9223372036854775807" in first.body
    page = json.loads(first.body)
    assert page["next_after"] is not None
    spec = json.dumps({"limit":1,"after":page["next_after"],"revision":page["revision"]}).encode()
    following = client.operation("POST", "/v1/query/packaged-ops", source=spec,
                                 content_type="application/json", token=read)
    assert following.revision == first.revision
    assert json.loads(following.body)["next_after"] is None
    patched = client.operation("PATCH", "/v1/collections/packaged-ops/documents/one",
                              source=b'{"$inc":{"value":1}}', content_type="application/json", token=write)
    assert json.loads(patched.body)["etag"] == patched.etag[1:-1]
    assert client.get("packaged-ops", "one", token=read).body == source.replace(b"value: 1", b"value: 2")
    exact = "# transaction bytes\r\nvalue: 9007199254740993\r\n"
    spec = json.dumps({"operations":[{"collection":"packaged-ops","document":"three","put":exact}]}).encode()
    receipt = client.operation("POST", "/v1/transactions", source=spec, content_type="application/json", token=write)
    assert json.loads(receipt.body)["operations"] == 1
    assert client.get("packaged-ops", "three", token=read).body == exact.encode()
    checkpoint = client.operation("GET", "/v1/changes", token=read)
    after = json.loads(checkpoint.body)["next_after"]
    client.put("packaged-ops", "later", source, token=write)
    pages = []
    result = client.feed("/v1/changes/stream?after=" + after + "&duration_ms=150&heartbeat_ms=100&limit=1",
                         pages.append, token=read)
    assert pages and all(type(raw) is bytes and raw.endswith(b"\n") for raw in pages)
    assert result.last_after != after
    assert result.last_after == json.loads(pages[-1])["next_after"]
    assert result.body == b""
print("PYTHON_INSTALLED_RAW_OPERATIONS_OK")
"""
        with native(root) as (ports, certificates, read, write):
            result = command(
                [python, "-I", "-c", program, str(ports["binary"]), certificates, read, write],
                cwd=python.parents[1],
                env=isolated_env(),
            )
        self.assertEqual(result.stdout, "PYTHON_INSTALLED_RAW_OPERATIONS_OK\n")

    def test_admin_extra_preserves_both_cli_names_and_explicit_schema(self):
        wheelhouse = os.environ.get("YAMORA_PACKAGE_WHEELHOUSE")
        if not wheelhouse:
            self.fail("YAMORA_PACKAGE_WHEELHOUSE must provide the existing optional PyYAML wheel")
        python = consumer(self.root / "admin-consumer", self.wheel)
        command(
            [
                python,
                "-I",
                "-m",
                "pip",
                "install",
                "--no-index",
                "--find-links",
                wheelhouse,
                f"{self.wheel}[admin]",
            ],
            cwd=python.parents[1],
            env=isolated_env(),
        )
        for name in ("yamoractl", "yamldbctl"):
            result = command(
                [python.parent / name, "--help"], cwd=python.parents[1], env=isolated_env()
            )
            self.assertIn("Query and administer", result.stdout)
        program = """
from pathlib import Path
import yamora.yamoractl, yamora.yamldbctl
from yamora.validation import load_schemas, validate_document
assert yamora.yamoractl.main is yamora.yamldbctl.main
schema = Path("schema.yaml")
schema.write_text("schema_version: 1\\ncollections:\\n  widgets:\\n    kinds:\\n      widget:\\n        required: [schema_version, kind, id]\\n")
validate_document(b"schema_version: 1\\nkind: widget\\nid: one\\n", "widgets", "one", load_schemas(schema))
print("PYTHON_ARTIFACT_ADMIN_OK")
"""
        result = command([python, "-I", "-c", program], cwd=python.parents[1], env=isolated_env())
        self.assertEqual(result.stdout, "PYTHON_ARTIFACT_ADMIN_OK\n")
        data = python.parents[1] / "data"
        (data / "widgets").mkdir(parents=True)
        (data / "widgets/one.yaml").write_bytes(b"schema_version: 1\nkind: widget\nid: one\n")
        for name in ("yamoractl", "yamldbctl"):
            result = command(
                [
                    python.parent / name,
                    "validate",
                    "--data-dir",
                    data,
                    "--schema",
                    python.parents[1] / "schema.yaml",
                ],
                cwd=python.parents[1],
                env=isolated_env(),
            )
            self.assertEqual(json.loads(result.stdout)["status"], "valid")
            self.assertEqual(json.loads(result.stdout)["documents"], 1)

    def test_builder_rejects_missing_or_symlinked_sources_and_checkout_output(self):
        spec = importlib.util.spec_from_file_location("python_package_builder", BUILDER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = self.root / "invalid-source"
        root.mkdir()
        with self.assertRaises(FileNotFoundError):
            module.inputs(root)
        (root / "LICENSE").symlink_to(ROOT / "LICENSE")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            module.inputs(root)
        with self.assertRaisesRegex(ValueError, "outside"):
            module.build(ROOT, ROOT / "dist")


class PythonBuilderLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=os.environ["TMPDIR"], prefix="builder-lifetime-"
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location("lifetime_builder", BUILDER)
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)

    def exercise(self, mode, *, uncertain=False):
        from tools.ci.yamora_driver_ci import process

        marker, heartbeat, stage_file = (self.root / name for name in ("pid", "beats", "stage"))
        for path in (marker, heartbeat, stage_file):
            path.unlink(missing_ok=True)
        child_code = (
            "import os, pathlib, signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "with open(sys.argv[3] + '/held-open', 'a') as held:\n"
            "    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
            "    while True:\n"
            "        held.write('live\\n'); held.flush()\n"
            "        with open(sys.argv[2], 'a') as beat: beat.write('live\\n')\n"
            "        time.sleep(.01)\n"
        )
        program = (
            "import os, pathlib, signal, subprocess, sys, time\n"
            f"pathlib.Path({str(stage_file)!r}).write_text(os.getcwd())\n"
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}, "
            f"{str(marker)!r}, {str(heartbeat)!r}, os.getcwd()], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "deadline=time.monotonic()+10\n"
            f"while not pathlib.Path({str(heartbeat)!r}).exists() or pathlib.Path({str(heartbeat)!r}).stat().st_size < 10:\n"
            "    if time.monotonic()>deadline: raise RuntimeError('fixture readiness failed')\n"
            "    time.sleep(.005)\n"
            f"if {mode!r} in ('interrupt', 'terminate'): os.kill(os.getppid(), "
            f"signal.SIGTERM if {mode!r} == 'terminate' else signal.SIGINT)\n"
            f"if {mode!r} in ('timeout', 'interrupt', 'terminate'): time.sleep(60)\n"
            f"else: raise SystemExit({7 if mode == 'nonzero' else 0})\n"
        )
        real_popen, leaders = subprocess.Popen, []

        class Backend(real_popen):
            def __init__(self, arguments, **options):
                arguments = list(arguments)
                arguments[arguments.index("-c") + 1] = program
                options["start_new_session"] = True  # Fixture owns a separate killable group.
                super().__init__(arguments, **options)
                leaders.append(self)

            def wait(self, timeout=None):
                return super().wait(timeout=0.5 if mode == "timeout" and timeout else timeout)

            def communicate(self, input=None, timeout=None):
                return super().communicate(input, timeout=0.5 if mode == "timeout" else timeout)

        failure = None
        try:
            with (
                mock.patch("subprocess.Popen", Backend),
                mock.patch.object(process, "TERM_GRACE_SECONDS", 0.05),
                mock.patch.object(process, "KILL_GRACE_SECONDS", 1),
                mock.patch.object(
                    process,
                    "_stop_group",
                    side_effect=process.ProcessGroupCleanupError("stop unverified"),
                )
                if uncertain
                else contextlib.nullcontext(),
            ):
                try:
                    output = self.root / ("dist-" + mode)
                    if mode == "terminate":
                        with mock.patch.object(
                            sys, "argv", [str(BUILDER), "--output", str(output)]
                        ):
                            self.builder.main()
                    else:
                        self.builder.build(ROOT, output)
                except (RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                    failure = error
            self.assertTrue(marker.is_file(), "real backend control must have started")
            self.assertGreaterEqual(heartbeat.stat().st_size, 10, "heartbeat control must advance")
            stage = Path(stage_file.read_text())
            if uncertain:
                self.assertIsInstance(failure, process.ProcessGroupCleanupError)
                self.assertTrue(stage.is_dir(), "unverified backend stage must be retained")
                self.assertFalse(
                    stage.is_relative_to(self.root), "retention must survive caller cleanup"
                )
                guard = stage.parent.parent / (".yamora-sdk-retained-" + stage.parent.name)
                self.assertTrue(guard.is_file(), "unverified workspace guard must remain")
            else:
                if mode == "success":
                    self.assertIsNone(failure)
                else:
                    self.assertIsNotNone(failure)
                state = Path("/proc") / marker.read_text() / "stat"
                if state.exists():
                    self.assertIn(
                        state.read_text().rsplit(")", 1)[1].split()[0],
                        ("Z", "X", "x"),
                        "LIVE_BACKEND_DESCENDANT_AFTER_BUILD",
                    )
                self.assertFalse(stage.exists(), "verified stage should be removed")
        finally:
            for leader in leaders:
                try:
                    os.killpg(leader.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                leader.wait(timeout=5)
                self.assertFalse(process._wait_group(leader, 2), "fixture group must stop")
            if stage_file.exists():
                stage = Path(stage_file.read_text())
                # Only this fixture's proven-stopped retained allocation is eligible.
                if stage.exists() and stage.parent.name.startswith("yamora-sdk-"):
                    shutil.rmtree(stage.parent)
                    (stage.parent.parent / (".yamora-sdk-retained-" + stage.parent.name)).unlink()

    def test_descendants_stop_before_success_failure_timeout_and_interrupt_cleanup(self):
        for mode in ("success", "nonzero", "timeout", "interrupt", "terminate"):
            with self.subTest(mode=mode):
                self.exercise(mode)

    def test_unverified_backend_cleanup_preserves_stage_and_guard(self):
        self.exercise("success", uncertain=True)


if __name__ == "__main__":
    unittest.main()
