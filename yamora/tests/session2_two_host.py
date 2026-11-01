"""Two-domain native qualification inputs and entrypoint.

Host SSH pipes are started by the parent, with BatchMode and strict host keys.
Both endpoints run in managed containers. No SSH keys or host networking enter
them; stdout is exclusively the existing opaque session2_stdio_mux protocol.
"""

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import select
import ssl
import stat
import struct
import subprocess
import time
import uuid
from pathlib import Path

from tools.shared.scratch import storage_root
from tools.shared.scratch import temporary_directory

GROUPS = ("control", "alpha", "beta")
NODES = tuple(f"{group}{i}" for group in GROUPS for i in (1, 2, 3))
OWNERS = (NODES[:6], NODES[6:])
IDENTITIES = ("http", "driver", *NODES)
MAX_REPLY = 4 * 1024 * 1024


class QualificationError(RuntimeError):
    pass


NATIVE_OPERATIONS = frozenset(
    {"gather", "aggregate", "route", "install", "migrate", "step", "state"}
)


class NativeHttpError(QualificationError):
    def __init__(self, operation, status):
        super().__init__("native HTTP status did not match the qualification contract")
        self.native_http = {"operation": operation, "status": status}


ERROR_TYPES = (
    (QualificationError, "QualificationError"),
    (AssertionError, "AssertionError"),
    (ssl.SSLCertVerificationError, "SSLCertVerificationError"),
    (ssl.SSLError, "SSLError"),
    (http.client.RemoteDisconnected, "RemoteDisconnected"),
    (http.client.HTTPException, "HTTPException"),
    (TimeoutError, "TimeoutError"),
    (ConnectionRefusedError, "ConnectionRefusedError"),
    (ConnectionResetError, "ConnectionResetError"),
    (BrokenPipeError, "BrokenPipeError"),
    (ConnectionError, "ConnectionError"),
    (OSError, "OSError"),
    (EOFError, "EOFError"),
    (KeyError, "KeyError"),
    (IndexError, "IndexError"),
    (TypeError, "TypeError"),
    (ValueError, "ValueError"),
    (AttributeError, "AttributeError"),
    (RuntimeError, "RuntimeError"),
)
ERROR_NAMES = frozenset(name for _, name in ERROR_TYPES) | {"Exception"}
ERROR_FILES = frozenset(
    {
        "session2_two_host.py",
        "session2_two_host_worker.py",
        "session2_two_host_driver.py",
        "session2_stdio_mux.py",
    }
)
WORKER_STAGES = frozenset(
    {
        "bootstrap",
        "scratch",
        "fleet",
        "mux",
        "control",
        "serve",
        "mux_close",
        "driver_join",
        "native_close",
        "signals_restore",
        "scratch_close",
        "result",
        "completion",
    }
)
SANITIZER_CATEGORIES = frozenset({"address", "undefined", "leak", "thread", "sanitizer"})


def public_failure(value):
    """Rebuild the public failure fields, ignoring all exception text and locals."""
    kind = value.get("error_type")
    kind = kind if isinstance(kind, str) and kind in ERROR_NAMES else "Exception"
    sites = []
    raw = value.get("error_sites", [])
    for item in raw[:8] if isinstance(raw, list) else ():
        if not isinstance(item, dict):
            continue
        filename, line = item.get("file"), item.get("line")
        if (
            isinstance(filename, str)
            and filename in ERROR_FILES
            and type(line) is int
            and 1 <= line <= 100000
        ):
            sites.append({"file": filename, "line": line})
    result = {"error_type": kind, "error_sites": sites}
    native = value.get("native_http")
    if (
        isinstance(native, dict)
        and isinstance(native.get("operation"), str)
        and native["operation"] in NATIVE_OPERATIONS
        and type(native.get("status")) is int
        and 100 <= native["status"] <= 599
    ):
        result["native_http"] = {key: native[key] for key in ("operation", "status")}
    if "stage" in value:
        stage = value.get("stage")
        result["stage"] = (
            stage if isinstance(stage, str) and stage in WORKER_STAGES else "bootstrap"
        )
    children = value.get("children")
    if isinstance(children, list):
        result["children"] = []
        for item in children[:9]:
            if (
                not isinstance(item, dict)
                or item.get("node") not in NODES
                or "returncode" not in item
            ):
                continue
            code = item.get("returncode")
            if code is not None and (type(code) is not int or not -255 <= code <= 255):
                continue
            if type(item.get("running")) is not bool or type(item.get("intentional")) is not bool:
                continue
            result["children"].append(
                {key: item[key] for key in ("node", "returncode", "running", "intentional")}
            )
    categories = value.get("sanitizers")
    if isinstance(categories, list):
        result["sanitizers"] = sorted(
            {
                item
                for item in categories[:8]
                if isinstance(item, str) and item in SANITIZER_CATEGORIES
            }
        )
    for key in ("driver_failure", "operation_failure"):
        cause = value.get(key)
        if isinstance(cause, dict):
            result[key] = public_failure(
                {field: cause.get(field) for field in ("error_type", "error_sites", "native_http")}
            )
    return result


def exception_details(error):
    """Read traceback coordinates without formatting source, locals or messages."""
    kind = next((name for cls, name in ERROR_TYPES if isinstance(error, cls)), "Exception")
    sites, frame, remaining = [], error.__traceback__, 64
    while frame is not None and remaining:
        filename = Path(frame.tb_frame.f_code.co_filename).name
        if filename in ERROR_FILES:
            sites.append({"file": filename, "line": frame.tb_lineno})
        frame, remaining = frame.tb_next, remaining - 1
    return public_failure(
        {
            "error_type": kind,
            "error_sites": sites[-8:],
            "native_http": getattr(error, "native_http", None),
        }
    )


def checked(value, message):
    if not value:
        raise QualificationError(message)


def verify_source(root, commit):
    checked(re.fullmatch("[0-9a-f]{40}", commit), "invalid candidate commit")
    root = Path(root).resolve()
    commands = (
        ("rev-parse", "--show-toplevel"),
        ("rev-parse", "HEAD"),
        ("status", "--porcelain", "--untracked-files=normal"),
    )
    results = [
        subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10, check=True
        ).stdout.strip()
        for args in commands
    ]
    checked(
        Path(results[0]).resolve() == root and results[1] == commit,
        "candidate source commit/root mismatch",
    )
    checked(not results[2], "candidate source must be clean and committed")


def pin_binary(path, digest):
    checked(re.fullmatch("[0-9a-f]{64}", digest), "invalid executable digest")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        checked(
            stat.S_ISREG(info.st_mode) and info.st_mode & 0o111,
            "candidate executable must be a regular executable",
        )
        with os.fdopen(os.dup(fd), "rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        checked(actual == digest, "candidate executable digest mismatch")
        after = os.fstat(fd)
        checked(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)
            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode),
            "candidate executable changed while pinning",
        )
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_json(path, limit=128 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        checked(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077
            and info.st_size <= limit,
            "fixture must be a private bounded regular file",
        )
        return json.load(stream)


def load_fixture(path):
    return validate_fixture(private_json(path))


def validate_fixture(value):
    checked(
        isinstance(value, dict) and set(value) == {"run_id", "ca", "identities", "read", "write"},
        "invalid qualification fixture fields",
    )
    checked(re.fullmatch("[0-9a-f]{32}", value["run_id"]), "invalid run identity")
    checked(
        isinstance(value["identities"], dict) and set(value["identities"]) == set(IDENTITIES),
        "qualification fixture identity set mismatch",
    )
    checked(isinstance(value["ca"], str) and len(value["ca"]) < 8192, "invalid test authority")
    for pair in value["identities"].values():
        checked(isinstance(pair, dict) and set(pair) == {"cert", "key"}, "invalid test identity")
        checked(
            all(isinstance(item, str) and 0 < len(item) < 8192 for item in pair.values()),
            "invalid test identity material",
        )
    for role in ("read", "write"):
        checked(
            isinstance(value[role], str) and re.fullmatch("[0-9a-f]{64}", value[role]),
            "invalid synthetic test credential",
        )
    return value


def read_fixture(descriptor, *, seconds=20):
    """Read a bounded private bootstrap before the opaque mux frames begin.

    The parent writes uint32 big-endian length + fixture JSON to each worker,
    then connects their stdio streams. Private bytes never become diagnostics.
    """
    deadline = time.monotonic() + seconds

    def exact(size):
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            checked(remaining > 0, "private fixture bootstrap deadline exceeded")
            if select.select([descriptor], [], [], min(remaining, 0.2))[0]:
                part = os.read(descriptor, size - len(result))
                checked(part, "private fixture bootstrap truncated")
                result.extend(part)
        return bytes(result)

    size = struct.unpack("!I", exact(4))[0]
    checked(0 < size <= 128 * 1024, "private fixture bootstrap exceeds byte budget")
    return validate_fixture(json.loads(exact(size)))


def private_write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value)


def prepare_fixture(output):
    output = Path(output)
    checked(
        output.resolve().is_relative_to(storage_root().resolve()),
        "fixture output must stay in owned disposable scratch",
    )
    with temporary_directory(prefix="two-host-certificates-") as root:

        def openssl(*args):
            subprocess.run(
                ["openssl", *map(str, args)], check=True, capture_output=True, timeout=20
            )

        authority, authority_key = root / "ca.pem", root / "ca.key"
        openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-keyout",
            authority_key,
            "-out",
            authority,
            "-days",
            "1",
            "-subj",
            "/CN=Session2 disposable authority",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        value = {
            "run_id": uuid.uuid4().hex,
            "ca": authority.read_text(),
            "identities": {},
            "read": secrets.token_hex(32),
            "write": secrets.token_hex(32),
        }
        for serial, name in enumerate(IDENTITIES, 10):
            key, request, certificate, extension = (
                root / f"{name}.{suffix}" for suffix in ("key", "csr", "pem", "ext")
            )
            purpose = (
                "serverAuth"
                if name == "http"
                else "clientAuth"
                if name == "driver"
                else "serverAuth,clientAuth"
            )
            san = "IP:127.0.0.1,DNS:localhost" if name == "http" else f"DNS:{name}.test"
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n"
            )
            openssl(
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                key,
                "-out",
                request,
                "-subj",
                f"/CN={name}.test",
            )
            openssl(
                "x509",
                "-req",
                "-in",
                request,
                "-CA",
                authority,
                "-CAkey",
                authority_key,
                "-set_serial",
                serial,
                "-days",
                "1",
                "-extfile",
                extension,
                "-out",
                certificate,
            )
            value["identities"][name] = {"cert": certificate.read_text(), "key": key.read_text()}
        private_write(output, json.dumps(value))


def materialize(fixture, root):
    root = Path(root)
    root.mkdir(mode=0o700)
    ca = root / "ca.pem"
    private_write(ca, fixture["ca"])
    files = {"ca": ca}
    for name, pair in fixture["identities"].items():
        paths = tuple(root / f"{name}.{suffix}" for suffix in ("pem", "key"))
        for path, field in zip(paths, ("cert", "key"), strict=True):
            private_write(path, pair[field])
        files[name] = paths
    return files


def client_context(material, identity="driver"):
    context = ssl.create_default_context(cafile=str(material["ca"]))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(*map(str, material[identity]))
    return context


def exchange(port, path, value=None, *, context, token=None, method="POST", timeout=12):
    checked(
        type(port) is int and 0 < port <= 65535 and port != 8000,
        "qualification endpoint must use a non-owner loopback port",
    )
    body = None if value is None else json.dumps(value).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=timeout)
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        payload = response.read(MAX_REPLY + 1)
        checked(len(payload) <= MAX_REPLY, "native response exceeded qualification budget")
        return response.status, json.loads(payload) if payload else None
    finally:
        connection.close()


def key_group(value):
    encoded = b"YSK\x01\x02\x00\x08" + value.to_bytes(8, "big", signed=True)
    return "alpha" if hashlib.sha256(encoded).digest()[0] < 128 else "beta"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare")
    prepare.add_argument("--output", type=Path, required=True)
    worker = actions.add_parser("worker")
    fixture = worker.add_mutually_exclusive_group(required=True)
    fixture.add_argument("--fixture", type=Path)
    fixture.add_argument("--fixture-stdin", action="store_true")
    worker.add_argument("--binary", type=Path, required=True)
    worker.add_argument("--sha256", required=True)
    worker.add_argument("--source-root", type=Path, required=True)
    worker.add_argument("--commit", required=True)
    worker.add_argument("--host-label", choices=("ThinkPad", "Precision"), required=True)
    worker.add_argument("--side", type=int, choices=(0, 1), required=True)
    worker.add_argument("--seconds", type=int, default=540)
    worker.add_argument("--rows", type=int, default=288)
    args = parser.parse_args()
    checked(os.environ.get("ANDROMEDA_TASK_CONTAINER"), "qualification requires a managed worker")
    if args.action == "prepare":
        prepare_fixture(args.output)
    else:
        from yamora.tests.session2_two_host_worker import run_worker

        try:
            run_worker(args)
        except QualificationError:
            # run_worker already emitted its allowlisted failure event.
            raise SystemExit(1) from None


if __name__ == "__main__":
    main()
