"""Owned native TLS lifecycle and isolated artifact consumers for package tests."""

import hashlib
import os
import re
import select
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from yamora.tests.test_binary_client import certs


def command(arguments, *, cwd, env=None, timeout=120):
    result = subprocess.run(
        list(map(str, arguments)),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise AssertionError(
            f"command failed ({result.returncode}):\n{result.stdout}{result.stderr}"
        )
    return result


def consumer(root, wheel):
    command([sys.executable, "-m", "venv", root], cwd=root.parent)
    python = root / "bin/python"
    command([python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", wheel], cwd=root)
    return python


def isolated_env():
    environment = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        environment.pop(key, None)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def native_binary():
    value = os.environ.get("YAMORA_TEST_BINARY")
    if not value or not Path(value).is_absolute():
        raise AssertionError("YAMORA_TEST_BINARY must name the supplied immutable executable")
    binary = Path(value).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise AssertionError("supplied daemon must be an executable file")
    return binary


@contextmanager
def native(root):
    binary = native_binary()
    digest = hashlib.sha256(binary.read_bytes()).digest()
    certificates, data = root / "certificates", root / "data"
    certificates.mkdir()
    data.mkdir()
    certs(certificates)
    read, write = root / "read-token", root / "write-token"
    read.write_text("r" * 32)
    write.write_text("w" * 32)
    read.chmod(0o600)
    write.chmod(0o600)
    environment = isolated_env()
    environment["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:abort_on_error=1"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    command(
        [binary, "--data-dir", data, "--init-disk", "--validate-only"],
        cwd=root,
        env=environment,
        timeout=30,
    )
    process = subprocess.Popen(
        [
            str(binary),
            "--data-dir",
            str(data),
            "--port",
            "0",
            "--binary-port",
            "0",
            "--auth-token-file",
            str(read),
            "--write-auth-token-file",
            str(write),
            "--tls-cert-file",
            str(certificates / "server.pem"),
            "--tls-key-file",
            str(certificates / "server.key"),
            "--tls-client-ca-file",
            str(certificates / "ca.pem"),
        ],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        deadline, pending, ports = time.monotonic() + 15, b"", {}
        while len(ports) < 2:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise AssertionError("native listener readiness deadline")
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                raise AssertionError("native exited before both listeners")
            pending += part
            if len(pending) > 8192:
                raise AssertionError("oversized native readiness output")
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                match = re.match(rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line)
                if match:
                    ports[match[1].decode()] = int(match[2])
        yield ports, certificates, read, write
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            _, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            raise AssertionError("owned daemon failed bounded shutdown") from None
        if process.returncode != 0 or b"Sanitizer" in stderr or b"runtime error:" in stderr:
            raise AssertionError("native daemon failed: " + stderr.decode(errors="replace"))
        if hashlib.sha256(binary.read_bytes()).digest() != digest:
            raise AssertionError("immutable native input changed")


def example_arguments(ports, certificates, read, write):
    return [
        "--port",
        str(ports["yamora"]),
        "--ca",
        str(certificates / "ca.pem"),
        "--cert",
        str(certificates / "client.pem"),
        "--key",
        str(certificates / "client.key"),
        "--read-token-file",
        str(read),
        "--write-token-file",
        str(write),
    ]
