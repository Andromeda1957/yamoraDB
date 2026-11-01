"""Mandatory acceptance on the parent's one integrated, immutable native daemon.

No build, fallback daemon, optional feature check or skip belongs in this suite.
"""

import contextlib
import hashlib
import http.client
import json
import os
import re
import signal
import ssl
import subprocess
import sys
import time
import unittest
from pathlib import Path

from tools.ci.yamora_driver_ci.process import run
from tools.ci.yamora_driver_ci.runner import immutable_daemon
from tools.ci.yamora_driver_ci.runner import native_binary
from tools.ci.yamora_driver_ci.runner import workspace
from tools.shared.scratch import is_managed_path
from tools.shared.scratch import storage_root
from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryConfig
from yamora.binary_reply import BinaryStatusError
from yamora.conformance.tests.native import owned_process

SCHEMA = b"# exact policy\r\ntype: object\r\nproperties:\r\n  n: {type: integer}\r\n  child:\r\n    type: object\r\n    properties: {flag: {type: boolean}}\r\n    required: [flag]\r\n    additionalProperties: false\r\nrequired: [n]\r\nadditionalProperties: false\r\n"
SOURCE = b"# native exact source\r\nn: 7 # preserved\r\n"
POLICY = "/v1/schema-policies/items"
DOCUMENT = "/v1/collections/items/documents/a"


def qualified_binary():
    configured = os.environ.get("YAMORA_SCHEMA_TEST_BINARY") or os.environ.get("YAMORA_TEST_BINARY")
    expected = os.environ.get("YAMORA_SCHEMA_CONFORMANCE_SHA256") or os.environ.get(
        "YAMORA_CONFORMANCE_SHA256"
    )
    if not configured or not re.fullmatch(r"[0-9a-f]{64}", expected or ""):
        raise AssertionError(
            "explicit qualified YAMORA_TEST_BINARY and SHA256 required; never skip/build"
        )
    binary = native_binary(configured)
    with binary.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise AssertionError("qualified schema daemon SHA256 mismatch")
    return binary, expected


@contextlib.contextmanager
def schema_workspace():
    with workspace(fixture_scratch_parent()) as root:
        yield root


def fixture_scratch_parent():
    """Attested disk-backed root; retention markers stay outside nested cases."""
    value = os.environ.get("TMPDIR")
    if not value:
        raise AssertionError("owned disk-backed task TMPDIR required")
    root = storage_root()
    # Broker-proven short aliases are intentional. Validate their containment,
    # but pass only the physical root to descriptor-walking native fixtures.
    temporary = Path(value)
    if (
        not temporary.is_absolute()
        or not temporary.is_dir()
        or temporary.stat().st_uid != os.getuid()
        or not is_managed_path(temporary)
    ):
        raise AssertionError("schema fixture requires owned managed TMPDIR")
    for path in (root,):
        if (
            not path.is_absolute()
            or not path.is_dir()
            or path.is_symlink()
            or path.resolve(strict=True) != path
            or path.stat().st_uid != os.getuid()
            or not is_managed_path(path)
        ):
            raise AssertionError("schema fixture requires canonical owned managed scratch")
    filesystem, depth = None, -1
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mount = Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4]))
        if root.is_relative_to(mount) and len(mount.parts) >= depth:
            filesystem, depth = fields[fields.index("-") + 1], len(mount.parts)
    if filesystem is None or filesystem in ("tmpfs", "ramfs", "hugetlbfs"):
        raise AssertionError("schema fixture requires a disk-backed filesystem")
    return root


class SchemaDaemon:
    """Own only this fixture's processes; preserve workspace on cleanup failure."""

    def __init__(
        self,
        root,
        *,
        data=None,
        initialize=True,
        schema=True,
        replica=False,
        tls=False,
        capabilities=None,
    ):
        self.root = Path(root)
        self.data = Path(data) if data is not None else self.root / "data"
        self.initialize, self.schema, self.replica, self.tls = (
            initialize,
            schema and capabilities is None,
            replica,
            tls,
        )
        self.capabilities = capabilities
        self.binary, self.expected = qualified_binary()
        self.stack = contextlib.ExitStack()
        self.records = []
        self.active = None
        self.env = {
            **os.environ,
            "TMPDIR": str(self.root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ASAN_OPTIONS": os.environ.get("ASAN_OPTIONS", "")
            + ":detect_leaks=1:halt_on_error=1:abort_on_error=1",
            "UBSAN_OPTIONS": os.environ.get("UBSAN_OPTIONS", "")
            + ":halt_on_error=1:print_stacktrace=1",
        }

    def command(self, *arguments, env=None, check=True):
        argv = [str(self.binary), *arguments]
        with owned_process(
            argv,
            env=self.env if env is None else env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        ) as child:
            stdout, stderr = child.communicate(timeout=60)
            result = subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
        if re.search(rb"Sanitizer|runtime error:", result.stderr):
            raise AssertionError(result.stderr)
        if check and result.returncode:
            raise AssertionError(
                f"actual native command failed ({result.returncode}): {result.stderr!r}"
            )
        return result

    def __enter__(self):
        try:
            self.stack.enter_context(immutable_daemon(self.binary))
            for name, value in (("read", "r"), ("write", "w"), ("scoped", "s")):
                path = self.root / name
                path.write_text(value * 32)
                path.chmod(0o600)
            self.access = self.root / "access.json"
            self.access.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roles": {"items": {"read": ["items"], "write": ["items"]}},
                        "principals": {
                            "items": {"token_file": str(self.root / "scoped"), "roles": ["items"]}
                        },
                    }
                )
            )
            self.access.chmod(0o600)
            if self.tls:
                run(
                    [sys.executable, "-m", "yamora.conformance.tests.certificates", str(self.root)],
                    cwd=Path(__file__).resolve().parents[2],
                    env=self.env,
                    timeout=30,
                )
            if self.initialize:
                self.data.mkdir(mode=0o700)
                self.command(
                    "--data-dir",
                    str(self.data),
                    "--init-disk",
                    "--validate-only",
                    *(("--schema-policies",) if self.schema else ()),
                    *(
                        ("--native-capabilities", str(self.capabilities))
                        if self.capabilities
                        else ()
                    ),
                )
            self.start()
            return self
        except BaseException:
            self.stack.close()
            raise

    def start(self, extra_environment=None):
        if self.active is not None:
            raise AssertionError("fixture already owns a running daemon")
        number = len(self.records)
        out_path, err_path = self.root / f"native-{number}.out", self.root / f"native-{number}.err"
        out = self.stack.enter_context(out_path.open("wb"))
        err = self.stack.enter_context(err_path.open("wb"))
        arguments = [
            str(self.binary),
            "--data-dir",
            str(self.data),
            "--port",
            "0",
            "--auth-token-file",
            str(self.root / "read"),
            "--write-auth-token-file",
            str(self.root / "write"),
            "--access-policy-file",
            str(self.access),
            "--cache-bytes",
            "32768",
            "--workers",
            "2",
            "--io-timeout-ms",
            "5000",
        ]
        if self.schema:
            arguments += ["--schema-policies"]
        if self.capabilities:
            arguments += ["--native-capabilities", str(self.capabilities)]
        if self.replica:
            arguments += ["--replica"]
        if self.tls:
            arguments += [
                "--binary-port",
                "0",
                "--tls-cert-file",
                str(self.root / "server.pem"),
                "--tls-key-file",
                str(self.root / "server.key"),
                "--tls-client-ca-file",
                str(self.root / "ca.pem"),
            ]
        process = self.stack.enter_context(
            owned_process(
                arguments,
                env={**self.env, **(extra_environment or {})},
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
            )
        )
        record = {"process": process, "out": out_path, "err": err_path, "expected": 0}
        self.records.append(record)
        self.active = record
        deadline = time.monotonic() + 15
        while True:
            self.check_logs()
            text = out_path.read_bytes()
            http = re.search(rb"^yamora listening on 127\.0\.0\.1:(\d+)", text, re.M)
            binary = re.search(rb"^binary listening on 127\.0\.0\.1:(\d+)", text, re.M)
            if http and (not self.tls or binary):
                self.port = int(http[1])
                self.binary_port = int(binary[1]) if binary else None
                if self.port == 8000 or self.binary_port == 8000:
                    raise AssertionError("owner port reserved")
                return
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError(
                    f"integrated schema daemon readiness failed: {err_path.read_bytes()!r}"
                )
            time.sleep(0.02)

    def check_logs(self):
        for record in self.records:
            if record["out"].stat().st_size > 8192 or record["err"].stat().st_size > 65536:
                raise AssertionError("native fixture log bound")
            errors = record["err"].read_bytes()
            if re.search(rb"Sanitizer|runtime error:", errors):
                raise AssertionError(errors)

    def stop(self, *, crash=False, already_crashed=False):
        record = self.active
        if record is None:
            return
        process = record["process"]
        if crash or already_crashed:
            record["expected"] = -signal.SIGKILL
        if process.poll() is None and not already_crashed:
            process.kill() if crash else process.terminate()
        process.wait(timeout=15)
        if process.returncode != record["expected"]:
            raise AssertionError(
                f"native shutdown {process.returncode}: {record['err'].read_bytes()!r}"
            )
        self.active = None
        self.check_logs()

    def context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(self.root / "ca.pem")
        context.load_cert_chain(self.root / "client.pem", self.root / "client.key")
        context.set_alpn_protocols(["http/1.1"])
        return context

    def request(self, method, target, body=b"", *, token=None, headers=None):
        if self.tls:
            connection = http.client.HTTPSConnection(
                "localhost", self.port, context=self.context(), timeout=10
            )
        else:
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(
                method,
                target,
                body,
                {
                    "Authorization": "Bearer "
                    + (
                        token
                        if token is not None
                        else ("r" if method in ("GET", "HEAD") else "w") * 32
                    ),
                    "Content-Type": "application/yaml",
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            payload = response.read(16 * 1024 * 1024 + 1)
            if len(payload) > 16 * 1024 * 1024:
                raise AssertionError("native response bound")
            return response.status, dict(response.getheaders()), payload
        finally:
            connection.close()

    def policy(self, source=SCHEMA, *, request_id="01" * 16, etag=None, method="PUT", token=None):
        headers = {"X-Yamora-Request-Id": request_id}
        headers.update({"If-Match": etag} if etag else {"If-None-Match": "*"})
        return self.request(
            method, POLICY, source if method == "PUT" else b"", token=token, headers=headers
        )

    def __exit__(self, *error):
        try:
            self.stop()
        finally:
            self.stack.__exit__(*error)


class SchemaPolicyStandaloneTests(unittest.TestCase):
    def test_http_patch_transaction_and_index_rejection_are_atomic(self):
        with schema_workspace() as root, SchemaDaemon(root) as daemon:
            self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
            accepted = daemon.policy()
            self.assertEqual(accepted[0], 201, accepted)
            indexes = {"indexes": [{"collection": "items", "name": "n", "fields": ["n"]}]}
            self.assertEqual(
                daemon.request("PUT", "/v1/indexes", json.dumps(indexes).encode())[0], 200
            )
            before = daemon.request("GET", DOCUMENT)
            catalog = daemon.request("GET", POLICY)
            self.assertEqual(catalog[0], 200, catalog)
            self.assertEqual(json.loads(catalog[2])["source"].encode(), SCHEMA)
            for body in (
                b"{}",
                b"n: null\n",
                b"n: false\n",
                b"n: '7'\n",
                b"n: 7\nextra: true\n",
                b"n: 7\nchild: {flag: 1}\n",
                b"n: 7\nchild: {flag: true, extra: null}\n",
            ):
                with self.subTest(body=body):
                    self.assertEqual(daemon.request("PUT", DOCUMENT, body)[0], 422)
                    self.assertEqual(daemon.request("GET", DOCUMENT), before)
            patch = json.dumps({"$set": {"n": "bad"}}).encode()
            self.assertEqual(daemon.request("PATCH", DOCUMENT, patch)[0], 422)
            operations = {
                "operations": [
                    {"collection": "items", "document": "b", "put": "n: 8\n"},
                    {"collection": "items", "document": "a", "put": "n: false\n"},
                ]
            }
            self.assertEqual(
                daemon.request("POST", "/v1/transactions", json.dumps(operations).encode())[0], 422
            )
            self.assertEqual(daemon.request("GET", DOCUMENT), before)
            self.assertEqual(daemon.request("GET", "/v1/collections/items/documents/b")[0], 404)
            self.assertEqual(daemon.request("GET", POLICY), catalog)
            query = daemon.request(
                "POST", "/v1/query/items", b'{"filter":{"n":7},"explain":true}', token="r" * 32
            )
            self.assertEqual(query[0], 200, query)
            self.assertEqual([d["id"] for d in json.loads(query[2])["documents"]], ["a"])
            self.assertEqual(daemon.request("DELETE", DOCUMENT)[0], 204)

    def test_activation_scans_existing_values_and_failure_publishes_no_receipt(self):
        with schema_workspace() as root, SchemaDaemon(root) as daemon:
            self.assertEqual(daemon.request("PUT", DOCUMENT, b"n: false\n")[0], 201)
            before = daemon.request("GET", DOCUMENT)
            rejected = daemon.policy()
            self.assertEqual(rejected[0], 422, rejected)
            self.assertEqual(daemon.request("GET", POLICY)[0], 404)
            self.assertEqual(daemon.request("GET", DOCUMENT), before)
            self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 200)
            self.assertEqual(
                daemon.policy()[0], 201, "failed activation must not reserve its request ID"
            )

    def test_exact_receipt_replay_after_later_changes_restart_and_current_auth(self):
        with schema_workspace() as root, SchemaDaemon(root) as daemon:
            first = daemon.policy()
            self.assertEqual(first[0], 201, first)
            changed = daemon.policy(
                SCHEMA + b"# version two\n", request_id="02" * 16, etag=first[1]["ETag"]
            )
            self.assertEqual(changed[0], 200, changed)
            off = daemon.policy(request_id="03" * 16, etag=changed[1]["ETag"], method="DELETE")
            self.assertEqual(off[0], 200, off)
            daemon.stop()
            daemon.start()
            self.assertEqual(
                daemon.policy(), first, "same ID replays exact original response, not latest policy"
            )
            self.assertEqual(daemon.policy(SCHEMA + b"# conflict\n")[0], 409)
            self.assertEqual(daemon.policy(etag=off[1]["ETag"], method="DELETE")[0], 409)
            other = daemon.request(
                "PUT",
                "/v1/schema-policies/other",
                SCHEMA,
                headers={"If-None-Match": "*", "X-Yamora-Request-Id": "01" * 16},
            )
            self.assertEqual(other[0], 409)
            self.assertIn(daemon.policy(token="x" * 32)[0], (401, 403))
            self.assertIn(daemon.policy(token="r" * 32)[0], (401, 403))
            self.assertIn(daemon.policy(token="s" * 32)[0], (401, 403))
            self.assertEqual(daemon.request("GET", POLICY, token="s" * 32)[0], 200)
            self.assertEqual(daemon.policy(etag=first[1]["ETag"], request_id="04" * 16)[0], 412)
            daemon.stop()
            physical = (daemon.data / ".yamora-disk").read_bytes()
            self.assertEqual(physical[:8], b"YAMDIS07")
            self.assertEqual(physical[4096:4104], b"YAMDIS07")

    def test_tls_binary_crud_uses_the_same_policy_admission(self):
        with schema_workspace() as root, SchemaDaemon(root, tls=True) as daemon:
            self.assertEqual(daemon.policy()[0], 201)
            config = BinaryConfig(
                host="127.0.0.1",
                port=daemon.binary_port,
                server_name="localhost",
                ca_pem=(root / "ca.pem").read_bytes(),
                client_cert_pem=(root / "client.pem").read_bytes(),
                client_key_pem=(root / "client.key").read_bytes(),
            )
            with BinaryClient(config) as client:
                stored = client.put("items", "a", SOURCE, token="w" * 32)
                self.assertEqual(stored.status, 201)
                for body in (b"{}", b"n: true\n", b"n: 1\nchild: {flag: 1}\n"):
                    with self.subTest(body=body), self.assertRaises(BinaryStatusError) as rejected:
                        client.put("items", "a", body, token="w" * 32)
                    self.assertEqual(rejected.exception.status, 422)
                    current = client.get("items", "a", token="r" * 32)
                    self.assertEqual((current.body, current.revision), (SOURCE, stored.revision))
                self.assertEqual(daemon.request("GET", DOCUMENT)[2], SOURCE)
                self.assertEqual(client.delete("items", "a", token="w" * 32).status, 204)
