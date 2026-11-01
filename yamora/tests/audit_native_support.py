"""Build the actual native helper/client in disposable fixture storage."""

import hashlib
import os
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "src/security"
COMMON = ("audit.c", "audit_codec.c", "audit_helper_codec.c")


def compile_native(output, sources, *, sanitize=True, wraps=()):
    command = [
        os.environ.get("CC", "/usr/bin/clang"),
        "-std=c17",
        "-O1",
        "-g",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-fno-omit-frame-pointer",
        "-I",
        str(SECURITY),
    ]
    if sanitize:
        command += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    command += [str(source) for source in sources]
    command += [f"-Wl,--wrap={name}" for name in wraps]
    command += ["-lcrypto", "-pthread", "-o", str(output)]
    subprocess.run(command, capture_output=True, text=True, timeout=90, check=True)
    output.parent.chmod(0o755)
    output.chmod(0o755)
    return output


def build_helper(directory, *, sanitize=True, helper_source=None):
    return compile_native(
        directory / "audit-helper",
        [
            helper_source if name == "audit_helper.c" and helper_source else SECURITY / name
            for name in (
                *COMMON,
                "audit_custody.c",
                "audit_client.c",
                "audit_helper.c",
                "audit_helper_main.c",
            )
        ],
        sanitize=sanitize,
    )


def build_client(directory, *, sanitize=True, client_source=None):
    return compile_native(
        directory / "audit-client",
        [
            ROOT / "tests/audit_client_harness.c",
            client_source or SECURITY / "audit_client.c",
            SECURITY / "audit_helper_codec.c",
            SECURITY / "audit_codec.c",
        ],
        sanitize=sanitize,
        wraps=("recvmsg",),
    )


def build_daemon(
    directory, *, sanitize=True, daemon_source=None, object_directory=None, source_overrides=None
):
    # Cache real translation units only within this fixture's disposable owner.
    # Header/source/flags changes invalidate objects; a guard mutant recompiles
    # its actual daemon TU and links the same qualified native support closure.
    flags = "-std=c17 -O0 -g -Wall -Wextra -Wpedantic -Werror -fno-omit-frame-pointer"
    if sanitize:
        flags += " -fsanitize=address,undefined -fno-sanitize-recover=all"
    target = directory / "daemon/yamora"
    result = subprocess.run(
        [
            "make",
            "-C",
            str(ROOT),
            "--dry-run",
            "CC=/usr/bin/clang",
            "CFLAGS=" + flags,
            "BUILD_DIR=" + str(target.parent),
            str(target),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith("/usr/bin/clang ")]
    if result.returncode or len(lines) != 1:
        raise AssertionError(result.stdout + result.stderr)
    command = shlex.split(lines[0])
    source_indexes = [i for i, word in enumerate(command) if word.endswith(".c")]
    prefix = command[: source_indexes[0]]
    tail = command[command.index("-o") + 2 :]
    header_digest = hashlib.sha256()
    for header in sorted((ROOT / "src").rglob("*.h")):
        header_digest.update(str(header.relative_to(ROOT)).encode())
        header_digest.update(header.read_bytes())
    common = header_digest.digest() + "\0".join(prefix).encode()
    cache = object_directory or directory / "daemon-objects"
    cache.mkdir(parents=True, exist_ok=True)
    objects = []
    for index in source_indexes:
        source = (
            Path(daemon_source)
            if command[index] == "src/daemon.c" and daemon_source
            else (source_overrides or {}).get(command[index], ROOT / command[index])
        )
        digest = hashlib.sha256(common + command[index].encode() + source.read_bytes()).hexdigest()
        obj = cache / (digest + ".o")
        if not obj.exists():
            compiled = subprocess.run(
                [*prefix, "-pthread", "-c", str(source), "-o", str(obj)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
        objects.append(str(obj))
    target.parent.mkdir(parents=True, exist_ok=True)
    linked = subprocess.run(
        [*prefix, *objects, "-o", str(target), *tail],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if linked.returncode:
        raise AssertionError(linked.stdout + linked.stderr)
    directory.chmod(0o755)
    target.parent.chmod(0o755)
    target.chmod(0o755)
    return target
