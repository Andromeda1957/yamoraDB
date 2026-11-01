"""Relocate a local CPack artifact and build its installed public example."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import shutil
import ssl
import subprocess
import tarfile
import tempfile
from pathlib import Path

import test_driver as fixture

from tools.ci.yamora_driver_ci.runner import scratch_parent


def run(args, *, cwd, env, success=True):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, timeout=120)
    if result.returncode != (0 if success else 1):
        raise AssertionError(
            f"command {args[0]} exited {result.returncode}: {result.stderr[-4000:]!r}"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    settings = json.loads(args.settings.read_text())
    source = Path(__file__).resolve().parents[1]
    parent = scratch_parent(os.environ["TMPDIR"])
    original = Path(os.environ["YAMORA_TEST_BINARY"]).resolve(strict=True)
    digest = hashlib.sha256(original.read_bytes()).digest()
    with tempfile.TemporaryDirectory(prefix="cpp-package-", dir=parent) as folder:
        root = Path(folder)
        env = dict(os.environ)
        for name in (
            "CPATH",
            "CPLUS_INCLUDE_PATH",
            "C_INCLUDE_PATH",
            "LIBRARY_PATH",
            "LD_LIBRARY_PATH",
        ):
            assert not any(
                Path(path).resolve().is_relative_to(source)
                or Path(path).resolve().is_relative_to(args.build)
                for path in env.get(name, "").split(os.pathsep)
                if path
            ), "consumer environment must exclude SDK checkout and producer build paths"
        native = root / "native"
        shutil.copy2(original, native)
        native.chmod(0o500)
        assert hashlib.sha256(native.read_bytes()).digest() == digest
        env["YAMORA_TEST_BINARY"] = str(native)
        config = settings["configuration"]
        cmake = settings["cmake"]
        cpack = str(Path(cmake).with_name("cpack"))
        run(
            [
                cpack,
                "--config",
                str(args.build / "CPackConfig.cmake"),
                "-G",
                "TGZ",
                "-C",
                config,
                "-B",
                str(root / "artifacts"),
            ],
            cwd=root,
            env=env,
        )
        artifacts = list((root / "artifacts").glob("*.tar.gz"))
        assert len(artifacts) == 1
        unpack = root / "unpacked"
        with tarfile.open(artifacts[0]) as package:
            members = package.getmembers()
            assert len(members) < 1000 and sum(m.size for m in members) < 256 * 1024 * 1024
            package.extractall(unpack, filter="data")
        prefixes = list(unpack.iterdir())
        assert len(prefixes) == 1
        prefix = root / "relocated"
        prefixes[0].rename(prefix)
        assert (prefix / "include/yamora/client.hpp").is_file()
        assert (prefix / "include/yamora/binary.hpp").is_file()
        assert (prefix / "share/licenses/yamora_cpp/LICENSE").read_bytes() == (
            source / "LICENSE"
        ).read_bytes()
        assert (prefix / "share/doc/yamora_cpp/README.md").is_file()
        # Reuse the producer's actual compiler, flags, generator and toolchain.
        # CMAKE_INSTALL_PREFIX describes the producer, not the relocated consumer.
        cache = settings["cache"]
        arguments = [
            f"-D{name}:{item['type']}={item['value']}"
            for name, item in cache.items()
            if name not in ("CMAKE_PREFIX_PATH", "CMAKE_MODULE_PATH", "BUILD_SHARED_LIBS")
        ]
        configs = list(prefix.rglob("yamora_cppConfig.cmake"))
        assert len(configs) == 1
        arguments += [
            f"-DCMAKE_PREFIX_PATH={prefix}",
            f"-Dyamora_cpp_DIR:PATH={configs[0].parent}",
            "-DCMAKE_MODULE_PATH=",
            "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
            "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]
        generator = ["-G", settings["generator"]]
        for flag, name in (("-A", "platform"), ("-T", "toolset")):
            if settings[name]:
                generator += [flag, settings[name]]
        consumer = prefix / "share/yamora_cpp/examples"
        build = root / "consumer"
        command = [
            cmake,
            "-S",
            str(consumer),
            "-B",
            str(build),
            *generator,
            *arguments,
        ]
        run(command, cwd=root, env=env)
        resolved = [
            line.split("=", 1)[1]
            for line in (build / "CMakeCache.txt").read_text().splitlines()
            if line.startswith("yamora_cpp_DIR:PATH=")
        ]
        assert len(resolved) == 1 and Path(resolved[0]).is_relative_to(prefix), (
            "consumer must resolve relocated artifact"
        )
        run([cmake, "--build", str(build), "--config", config, "-j1"], cwd=root, env=env)
        executable = (
            build / config / "yamora_crud"
            if (build / config / "yamora_crud").is_file()
            else build / "yamora_crud"
        )
        # Link every existing public client through the relocated exported target.
        check = root / "binary-consumer"
        check.mkdir()
        (check / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(binary_check LANGUAGES CXX)\n"
            "find_package(yamora_cpp 0.1.0 EXACT CONFIG REQUIRED)\n"
            "add_executable(binary_check main.cpp)\ntarget_link_libraries(binary_check PRIVATE yamora::cpp)\n"
            "get_target_property(package_includes yamora::cpp INTERFACE_INCLUDE_DIRECTORIES)\n"
            'file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/artifact-$<CONFIG>.txt" '
            'CONTENT "$<TARGET_FILE:yamora::cpp>\\n${package_includes}\\n")\n'
        )
        (check / "main.cpp").write_text(
            "#include <yamora/binary.hpp>\n"
            "template<class F> bool rejects(F f){try{f();return false;}catch(const yamora::Error&){return true;}}\n"
            "int main(){yamora::Config http;http.port=0;\n"
            "return rejects([&]{yamora::Client c(http);}) && "
            "rejects([]{yamora::ClusterClient c(yamora::ClusterConfig{});}) && "
            "rejects([]{yamora::BinaryClient c(yamora::BinaryConfig{});}) ? 0 : 1;}\n"
        )
        run(
            [
                cmake,
                "-S",
                str(check),
                "-B",
                str(root / "binary-build"),
                *generator,
                *arguments,
            ],
            cwd=root,
            env=env,
        )
        resolved_paths = (root / "binary-build" / f"artifact-{config}.txt").read_text().splitlines()
        assert len(resolved_paths) == 2
        for path in [resolved_paths[0], *resolved_paths[1].split(";")]:
            assert Path(path).resolve(strict=True).is_relative_to(prefix), (
                f"public headers and library must resolve inside the relocated artifact: {path}"
            )
        # For shared packages, prefer this artifact's SONAME over loader defaults.
        # Retain loader paths needed by the configured system dependencies.
        library_directory = str(Path(resolved_paths[0]).parent)
        env["LD_LIBRARY_PATH"] = library_directory + (
            os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""
        )
        for project in (build, root / "binary-build"):
            commands = (project / "compile_commands.json").read_text()
            assert str(source) not in commands and str(args.build) not in commands, (
                "consumer compilation must exclude SDK checkout and producer build paths"
            )
        run(
            [cmake, "--build", str(root / "binary-build"), "--config", config, "-j1"],
            cwd=root,
            env=env,
        )
        binary_check = root / "binary-build" / config / "binary_check"
        if not binary_check.is_file():
            binary_check = root / "binary-build/binary_check"
        run([str(binary_check)], cwd=root, env=env)
        incompatible = root / "incompatible"
        incompatible.mkdir()
        (incompatible / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\nproject(incompatible LANGUAGES CXX)\n"
            "find_package(yamora_cpp 0.2.0 CONFIG REQUIRED)\n"
        )
        rejected = run(
            [
                cmake,
                "-S",
                str(incompatible),
                "-B",
                str(root / "incompatible-build"),
                *generator,
                *arguments,
            ],
            cwd=root,
            env=env,
            success=False,
        )
        assert b"0.2.0" in rejected.stderr and b"0.1.0" in rejected.stderr, (
            "version rejection must identify incompatible package"
        )
        # Reuse only the existing cert/daemon lifecycle, without running its suite.
        fixture.PROBE = str(executable)
        previous_binary = os.environ["YAMORA_TEST_BINARY"]
        os.environ["YAMORA_TEST_BINARY"] = str(native)
        try:
            fixture.setUpModule()
            with fixture.daemon(mutual=True) as port:
                example_env = dict(
                    env,
                    YAMORA_HOST="127.0.0.1",
                    YAMORA_PORT=str(port),
                    YAMORA_READ_TOKEN=fixture.READ,
                    YAMORA_WRITE_TOKEN=fixture.WRITE,
                    YAMORA_CA_FILE=str(fixture.CERTS / "ca.pem"),
                    YAMORA_CLIENT_CERT=str(fixture.CERTS / "client.pem"),
                    YAMORA_CLIENT_KEY=str(fixture.CERTS / "client.key"),
                )
                run(
                    [str(executable)],
                    cwd=root,
                    env=dict(example_env, YAMORA_WRITE_TOKEN="x" * 32),
                    success=False,
                )
                result = run([str(executable)], cwd=root, env=example_env)
                assert result.stdout == b"source-preserving CRUD passed\n"
                context = ssl.create_default_context(cafile=example_env["YAMORA_CA_FILE"])
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(
                    example_env["YAMORA_CLIENT_CERT"], example_env["YAMORA_CLIENT_KEY"]
                )
                with contextlib.closing(
                    http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
                ) as connection:
                    connection.request(
                        "GET",
                        "/v1/collections/examples/documents/package-crud",
                        headers={"Authorization": "Bearer " + fixture.READ},
                    )
                    response = connection.getresponse()
                    assert response.status == 404, "example must delete its document"
                    response.read()
        finally:
            fixture.tearDownModule()
            os.environ["YAMORA_TEST_BINARY"] = previous_binary
            assert hashlib.sha256(original.read_bytes()).digest() == digest
            assert hashlib.sha256(native.read_bytes()).digest() == digest
        print(
            "C++ package: artifact-only headers/library, all public clients, version rejection, denied write and native mTLS CRUD passed"
        )


if __name__ == "__main__":
    main()
