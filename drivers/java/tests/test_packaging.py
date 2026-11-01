"""Local JAR consumer acceptance; --acceptance also qualifies the Node tarball.

The optional launcher reuses the repository's pinned provisioner and process
supervisor. It runs only these two packaging tests, never the SDK foundations.
"""

import argparse
import os
import shutil
import sys
import unittest
import zipfile
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("YAMORA_PACKAGE_SOURCE_ROOT", Path(__file__).resolve().parents[4]))


def shared_support():
    if not (SOURCE / "tools/ci/yamora_driver_ci/runner.py").is_file():
        raise RuntimeError(
            "set YAMORA_PACKAGE_SOURCE_ROOT to the managed repository fixture source"
        )
    sys.path.insert(0, str(SOURCE))


class PackagingTests(unittest.TestCase):
    def test_jars_compile_external_consumer_and_run_tls_example(self):
        shared_support()
        from tools.ci.yamora_driver_ci.process import RunnerError
        from tools.ci.yamora_driver_ci.process import run
        from tools.ci.yamora_driver_ci.runner import workspace
        from yamora.conformance.tests.native import Native

        # The shared workspace preserves a failed shutdown's retention guard.
        with workspace(Path(os.environ["TMPDIR"])) as root:
            environment = dict(os.environ, TMPDIR=str(root), PYTHONPATH=str(SOURCE))
            for name in ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
                environment.pop(name, None)

            def command(*args, cwd=root):
                return run(list(args), cwd=cwd, env=environment, timeout=90)

            artifacts = root / "artifacts"
            command("sh", str(SDK / "build.sh"), str(artifacts))
            version = (SDK / "VERSION").read_text().strip()
            jar = artifacts / f"yamora-java-{version}.jar"
            sources = artifacts / f"yamora-java-{version}-sources.jar"
            with zipfile.ZipFile(jar) as package:
                names = package.namelist()
                self.assertEqual(package.read("META-INF/LICENSE"), (SDK / "LICENSE").read_bytes())
                manifest = package.read("META-INF/MANIFEST.MF").decode()
                self.assertIn(f"Implementation-Version: {version}\r\n", manifest)
                self.assertIn("Automatic-Module-Name: io.yamora.driver\r\n", manifest)
                for name in names:
                    if not name.endswith("/"):
                        self.assertTrue(
                            name.startswith("io/yamora/")
                            and name.endswith(".class")
                            or name in ("META-INF/LICENSE", "META-INF/MANIFEST.MF"),
                            name,
                        )
                    if name.endswith(".class"):
                        self.assertEqual(package.read(name)[:8], b"\xca\xfe\xba\xbe\x00\x00\x00=")
                required = {
                    f"io/yamora/{path.stem}.class"
                    for path in (SDK / "src/io/yamora").glob("*.java")
                }
                self.assertTrue(required.issubset(names), sorted(required - set(names)))
            consumer = root / "external consumer"
            consumer.mkdir()
            classes = consumer / "classes"
            classes.mkdir()
            empty = consumer / "empty-source-path"
            empty.mkdir()
            class_names = consumer / "classes.txt"
            class_names.write_text(
                "\n".join(name[:-6].replace("/", ".") for name in sorted(required)) + "\n"
            )
            with zipfile.ZipFile(sources) as package:
                expected = {
                    str(path.relative_to(SDK / "src")): path.read_bytes()
                    for path in (SDK / "src").rglob("*.java")
                }
                expected.update(
                    {
                        name: (SDK / name).read_bytes()
                        for name in ("LICENSE", "README.md", "examples/Crud.java")
                    }
                )
                self.assertEqual(
                    {name for name in package.namelist() if not name.endswith("/")},
                    set(expected) | {"META-INF/MANIFEST.MF"},
                )
                for name, content in expected.items():
                    self.assertEqual(package.read(name), content, name)
                (consumer / "Crud.java").write_bytes(package.read("examples/Crud.java"))
            (consumer / "Consumer.java").write_text("""
import io.yamora.*;
public final class Consumer {
    private Consumer() {}
    public static void main(String[] args) throws Exception {
        var artifact = java.nio.file.Path.of(args[1]).toRealPath();
        for (String name : java.nio.file.Files.readAllLines(java.nio.file.Path.of(args[0]))) {
            var type = Class.forName(name, false, Consumer.class.getClassLoader());
            var location = java.nio.file.Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (!artifact.equals(location.toRealPath())) throw new AssertionError("non-artifact SDK class");
        }
        if (!"0.1.0".equals(YamoraClient.class.getPackage().getImplementationVersion()))
            throw new AssertionError("artifact version");
        var client = new YamoraClient("127.0.0.1", 8765, "", "", null);
        if (client == null) throw new AssertionError("artifact client");
        System.out.println("external JAR consumer passed");
    }
}
""")
            for name in ("Adapter.java", "HttpReplicaAdapter.java"):
                shutil.copyfile(SDK / "conformance" / name, consumer / name)
            command(
                "javac",
                "-J-XX:-UsePerfData",
                "-J-Xmx384m",
                f"-J-Djava.io.tmpdir={root}",
                "--release",
                "17",
                "-Xlint:all",
                "-Werror",
                "-sourcepath",
                str(empty),
                "-cp",
                str(jar),
                "-d",
                str(classes),
                "Consumer.java",
                "Crud.java",
                "Adapter.java",
                "HttpReplicaAdapter.java",
                cwd=consumer,
            )
            options = (
                "java",
                "-XX:ActiveProcessorCount=2",
                "-XX:-UsePerfData",
                "-Xmx384m",
                f"-Djava.io.tmpdir={root}",
                "-cp",
                str(classes) + os.pathsep + str(jar),
            )
            self.assertIn(
                "external JAR consumer passed",
                command(*options, "Consumer", str(class_names), str(jar), cwd=consumer),
            )
            # Withhold one implementation from each transport in disposable JARs.
            # The same external consumer must fail instead of finding SDK sources.
            for missing in ("HttpTransport", "ClusterTransport", "BinaryFrameCodec"):
                incomplete = artifacts / f"without-{missing}.jar"
                with zipfile.ZipFile(jar) as original, zipfile.ZipFile(incomplete, "w") as altered:
                    for entry in original.infolist():
                        if entry.filename != f"io/yamora/{missing}.class":
                            altered.writestr(entry, original.read(entry.filename))
                broken_options = (*options[:-1], str(classes) + os.pathsep + str(incomplete))
                with self.assertRaises(RunnerError):
                    command(
                        *broken_options, "Consumer", str(class_names), str(incomplete), cwd=consumer
                    )
                self.assertIn(
                    f"ClassNotFoundException: io.yamora.{missing}",
                    (root / "command.log").read_text(),
                )
            self.assertIn(
                "external JAR consumer passed",
                command(*options, "Consumer", str(class_names), str(jar), cwd=consumer),
            )
            native_root = root / "native"
            native_root.mkdir()
            binary = Path(os.environ["YAMORA_TEST_BINARY"])
            with Native(native_root, binary, environment=environment) as native:
                command(
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-inkey",
                    str(native_root / "client.key"),
                    "-in",
                    str(native_root / "client.pem"),
                    "-certfile",
                    str(native_root / "ca.pem"),
                    "-passout",
                    "pass:test-only-password",
                    "-out",
                    str(native_root / "client.p12"),
                )
                environment.update(
                    {
                        "YAMORA_HOST": "127.0.0.1",
                        "YAMORA_PORT": str(native.http_port),
                        "YAMORA_READ_TOKEN": "r" * 32,
                        "YAMORA_WRITE_TOKEN": "w" * 32,
                        "YAMORA_CA_FILE": str(native_root / "ca.pem"),
                        "YAMORA_IDENTITY_FILE": str(native_root / "client.p12"),
                        "YAMORA_IDENTITY_PASSWORD": "test-only-password",
                    }
                )
                self.assertIn(
                    "Yamora Java package CRUD passed", command(*options, "Crud", cwd=consumer)
                )
                self.assertEqual(native.http("GET", "examples", "java-package-crud")["status"], 404)


def acceptance(binary, expected_digest, suites):
    """Run inside the managed environment; provision only private pinned tools."""
    shared_support()
    from tools.ci.yamora_driver_ci.process import ProcessGroupCleanupError
    from tools.ci.yamora_driver_ci.process import RunnerError
    from tools.ci.yamora_driver_ci.process import run
    from tools.ci.yamora_driver_ci.runner import copy_sdk
    from tools.ci.yamora_driver_ci.runner import environment
    from tools.ci.yamora_driver_ci.runner import immutable_daemon
    from tools.ci.yamora_driver_ci.runner import prepare_tools
    from tools.ci.yamora_driver_ci.runner import scratch_parent
    from tools.ci.yamora_driver_ci.runner import workspace

    with immutable_daemon(binary) as original_digest:
        if original_digest != expected_digest:
            raise RuntimeError("supplied immutable native input digest mismatch")
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            native = root / "yamora"
            shutil.copyfile(binary, native)
            native.chmod(0o700)
            with immutable_daemon(native) as copied_digest:
                if copied_digest != original_digest:
                    raise RuntimeError("copied native input digest mismatch")
                env = environment(root, native, dict(os.environ), jobs=2)
                env.update(YAMORA_PACKAGE_SOURCE_ROOT=str(SOURCE), PYTHONPATH=str(SOURCE))
                tools = prepare_tools(tuple(suites), {}, root, env, True, 2, SOURCE)
                # Current shared tool selection exposes node/java/javac only.
                # Package acceptance additionally needs npm and jar from the same pins.
                packaging_tools = {}
                if "node" in suites:
                    packaging_tools["npm"] = tools["node"].parent / "npm"
                if "java" in suites:
                    packaging_tools["jar"] = tools["javac"].parent / "jar"
                for name, executable in packaging_tools.items():
                    if not executable.is_file() or not os.access(executable, os.X_OK):
                        raise RuntimeError(f"missing pinned packaging tool: {name}")
                    (root / "bin" / name).symlink_to(executable)
                    run([name, "--version"], cwd=root, env=env, timeout=30)
                sdks = {suite: copy_sdk(SOURCE, root, suite) for suite in suites}
                commands = []
                if "node" in sdks:
                    node = sdks["node"]
                    commands.append((["node", "--test", str(node / "tests/package.test.js")], node))
                if "java" in sdks:
                    java = sdks["java"]
                    commands.append(([sys.executable, str(java / "tests/test_packaging.py")], java))
                failures = []
                for command, directory in commands:
                    try:
                        run(command, cwd=directory, env=env, timeout=180, tests=True)
                    except ProcessGroupCleanupError:
                        raise
                    except RunnerError as error:
                        failures.append(str(error))
                if failures:
                    raise RunnerError("; ".join(failures))
                print(
                    f"PASS: {', '.join(suites)} packaged consumers and native mTLS CRUD; daemon SHA256 {copied_digest}",
                    flush=True,
                )


if __name__ == "__main__":
    if "--acceptance" in sys.argv:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--acceptance", action="store_true")
        parser.add_argument("--binary", type=Path, required=True)
        parser.add_argument("--sha256", required=True)
        parser.add_argument("--suite", action="append", choices=("node", "java"))
        arguments = parser.parse_args()
        acceptance(arguments.binary, arguments.sha256, arguments.suite or ("node", "java"))
    else:
        unittest.main()
