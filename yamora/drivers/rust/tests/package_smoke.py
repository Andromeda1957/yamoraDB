"""Build a local crate, then compile and run its public example from that artifact."""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import re
import selectors
import shutil
import ssl
import subprocess
import sys
import tarfile
from pathlib import Path

from support.fixture import certificates

# The qualification harness is test-only; compiled consumers resolve only the crate.
repository = Path(__file__).resolve().parents[4]
if (repository / "tools/ci/yamora_driver_ci").is_dir():
    sys.path.insert(0, str(repository))

from tools.ci.yamora_driver_ci.runner import package_task_root  # noqa: E402
from tools.ci.yamora_driver_ci.runner import scratch_parent  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402
from yamora.conformance.tests.native import owned_process  # noqa: E402


def staging_parent():
    # A Rust/Python child exit cannot carry cleanup exceptions through cargo.
    # Keep uncertain native state outside every disposable caller allocation.
    return package_task_root(scratch_parent(os.environ["TMPDIR"]))


def run(args, *, cwd, env, success=True):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, timeout=120)
    if result.returncode != (0 if success else 1):
        # Commands contain paths and fixed flags only, never credentials.
        raise AssertionError(
            f"command {args[0]} exited {result.returncode}: {result.stderr[-4000:]!r}"
        )
    return result


@contextlib.contextmanager
def native(root, env):
    original = Path(env["YAMORA_TEST_BINARY"]).resolve(strict=True)
    digest = hashlib.sha256(original.read_bytes()).digest()
    binary = root / "native"
    shutil.copy2(original, binary)
    binary.chmod(0o500)
    assert hashlib.sha256(binary.read_bytes()).digest() == digest
    certs = root / "certs"
    certs.mkdir(mode=0o700)
    certificates(certs)
    database = root / "db"
    database.mkdir(mode=0o700)
    for name, token in (("read", "r" * 32), ("write", "w" * 32)):
        path = root / f"{name}.token"
        path.write_text(token)
        path.chmod(0o600)
    run(
        [str(binary), "--data-dir", str(database), "--init-disk", "--validate-only"],
        cwd=root,
        env=env,
    )
    args = [
        str(binary),
        "--data-dir",
        str(database),
        "--port",
        "0",
        "--auth-token-file",
        str(root / "read.token"),
        "--write-auth-token-file",
        str(root / "write.token"),
        "--tls-cert-file",
        str(certs / "server.pem"),
        "--tls-key-file",
        str(certs / "server.key"),
        "--tls-client-ca-file",
        str(certs / "ca.pem"),
    ]
    with (
        (root / "native.log").open("w+") as log,
        owned_process(args, env=env, stdout=subprocess.PIPE, stderr=log) as child,
        child.stdout,
    ):
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                assert selector.select(20), "native startup deadline"
            banner = child.stdout.readline(1024)
            match = re.match(rb"^yamora listening on 127\.0\.0\.1:(\d+) ", banner)
            assert match, f"invalid native banner {banner!r}"
            port = int(match[1])
            assert port != 8000
            example_env = dict(
                env,
                YAMORA_HOST="127.0.0.1",
                YAMORA_PORT=str(port),
                YAMORA_READ_TOKEN="r" * 32,
                YAMORA_WRITE_TOKEN="w" * 32,
                YAMORA_CA_FILE=str(certs / "ca.pem"),
                YAMORA_CLIENT_CERT=str(certs / "client.pem"),
                YAMORA_CLIENT_KEY=str(certs / "client.key"),
            )
            yield example_env
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            child.stdout.close()
            log.seek(0)
            output = log.read()
            assert child.returncode == 0, (
                f"native teardown exited {child.returncode}: {output[-2000:]}"
            )
            assert not any(
                text in output for text in ("AddressSanitizer", "LeakSanitizer", "runtime error:")
            ), output[-2000:]
            assert hashlib.sha256(original.read_bytes()).digest() == digest
            assert hashlib.sha256(binary.read_bytes()).digest() == digest


def main():
    source = Path(__file__).resolve().parents[1]
    with workspace(staging_parent()) as root:
        env = dict(os.environ)
        for key, name in (
            ("HOME", "home"),
            ("CARGO_HOME", "cargo-home"),
            ("CARGO_TARGET_DIR", "target"),
            ("TMPDIR", "tmp"),
        ):
            path = root / name
            path.mkdir()
            env[key] = str(path)
        env["CARGO_NET_OFFLINE"] = "true"
        cargo = env.get("CARGO", "cargo")
        run([cargo, "package", "--offline", "--locked", "--allow-dirty"], cwd=source, env=env)
        artifact = root / "target/package/yamora-0.1.0.crate"
        unpack = root / "unpacked"
        with tarfile.open(artifact) as package:
            members = package.getmembers()
            assert len(members) < 1000 and sum(m.size for m in members) < 16 * 1024 * 1024
            package.extractall(unpack, filter="data")
        packaged = unpack / "yamora-0.1.0"
        for name in (
            "LICENSE",
            "README.md",
            "examples/raw.rs",
            "examples/crud.rs",
            "src/lib.rs",
            "src/binary.rs",
            "src/tests/json.rs",
            "tests/support/fixture.py",
            "tests/package.rs",
            "tests/test_package_lifecycle.py",
        ):
            assert (packaged / name).is_file(), f"missing package file {name}"
        assert (packaged / "LICENSE").read_bytes() == (source / "LICENSE").read_bytes()
        assert not (packaged / "conformance").exists()
        # Move the unpacked artifact before resolving the external dependency.
        relocated = root / "relocated"
        packaged.rename(relocated)
        consumer = root / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(
            '[package]\nname="package-consumer"\nversion="0.0.0"\nedition="2024"\n'
            '[workspace]\n[dependencies]\nyamora={path="../relocated",version="=0.1.0"}\n'
        )
        shutil.copy2(relocated / "examples/crud.rs", consumer / "src/main.rs")
        (consumer / "src/bin").mkdir()
        (consumer / "src/bin/public_clients.rs").write_text(
            "use yamora::{Client,Config,ClusterClient,ClusterConfig,BinaryClient,BinaryConfig,BinaryTlsConfig};\n"
            "fn main(){\n"
            'assert!(Client::new(Config::new("127.0.0.1:0")).is_err());\n'
            "assert!(ClusterClient::new(ClusterConfig::new(Vec::new(),3)).is_err());\n"
            'let tls=BinaryTlsConfig{root_pem:Vec::new(),server_name:"127.0.0.1".into(),identity:None};\n'
            'assert!(BinaryClient::new(BinaryConfig::new("127.0.0.1:0".into(),tls)).is_err());\n}\n'
        )
        env["CARGO_TARGET_DIR"] = str(root / "consumer-target")
        metadata = json.loads(
            run(
                [cargo, "metadata", "--offline", "--format-version=1"], cwd=consumer, env=env
            ).stdout
        )
        libraries = [package for package in metadata["packages"] if package["name"] == "yamora"]
        assert len(libraries) == 1
        assert Path(libraries[0]["manifest_path"]).resolve() == relocated / "Cargo.toml", (
            "Cargo must resolve yamora solely from the extracted artifact"
        )
        assert all(
            Path(package["manifest_path"]).resolve().is_relative_to(root)
            for package in metadata["packages"]
        ), "consumer dependency resolution must exclude the SDK checkout"
        run([cargo, "build", "--offline"], cwd=consumer, env=env)
        run([str(root / "consumer-target/debug/public_clients")], cwd=consumer, env=env)
        executable = root / "consumer-target/debug/package-consumer"
        with native(root, env) as example_env:
            # Bad write authority must reach the real service and fail.
            denied = dict(example_env, YAMORA_WRITE_TOKEN="x" * 32)
            run([str(executable)], cwd=consumer, env=denied, success=False)
            result = run([str(executable)], cwd=consumer, env=example_env)
            assert result.stdout == b"source-preserving CRUD passed\n"
            context = ssl.create_default_context(cafile=example_env["YAMORA_CA_FILE"])
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(
                example_env["YAMORA_CLIENT_CERT"], example_env["YAMORA_CLIENT_KEY"]
            )
            with contextlib.closing(
                http.client.HTTPSConnection(
                    "127.0.0.1", int(example_env["YAMORA_PORT"]), context=context, timeout=5
                )
            ) as connection:
                connection.request(
                    "GET",
                    "/v1/collections/examples/documents/package-crud",
                    headers={"Authorization": "Bearer " + example_env["YAMORA_READ_TOKEN"]},
                )
                response = connection.getresponse()
                assert response.status == 404, "example must delete its document"
                response.read()
        print(
            "Rust package: inventory, artifact-only Cargo resolution, all public clients, denied write and native mTLS CRUD passed"
        )


if __name__ == "__main__":
    main()
