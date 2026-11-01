"""Run both v2 CLI adapters against synthetic peers, without native builds.

Set TMPDIR to an owned scratch directory and select php, csharp or both with
YAMORA_HTTP_REPLICA_TEST_LANGUAGE (default both). Selected runtimes come from
PATH. Supply absolute YAMORA_HTTP_REPLICA_PHP_ADAPTER and/or
YAMORA_HTTP_REPLICA_CSHARP_DLL paths. No package or SDK installation is used.
"""

import contextlib
import copy
import json
import os
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from peers import CLUSTER
from peers import REVISION
from peers import SOURCE
from peers import Peer
from peers import certificates

COMMAND = "yamora-http-replica-command/2"
OBSERVATION = "yamora-http-replica-observation/2"
OBS_KEYS = {
    "schema",
    "seq",
    "action",
    "outcome",
    "error_kind",
    "elapsed_ns",
    "api",
    "sdk_request_id",
    "envelope",
    "recovery_mode",
    "recovery_handle",
}
API_KEYS = {"status", "body_file", "etag", "revision", "receipt"}


def command(seq=1, action="call", **fields):
    value = {"schema": COMMAND, "seq": seq, "action": action}
    if action == "call":
        value.update(
            method="PATCH",
            collection="manifests",
            document="counter",
            source_file="input/patch.bin",
            request_id=None,
            if_match=None,
            if_none_match=None,
        )
    return value | fields


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def selected_languages():
    selection = os.environ.get("YAMORA_HTTP_REPLICA_TEST_LANGUAGE", "both")
    if selection not in ("php", "csharp", "both"):
        raise RuntimeError("YAMORA_HTTP_REPLICA_TEST_LANGUAGE must be php, csharp or both")
    return ("php", "csharp") if selection == "both" else (selection,)


def runner_configuration():
    directory = os.environ.get("TMPDIR", "")
    scratch = Path(directory)
    if not directory or not scratch.is_absolute() or scratch.resolve() != scratch:
        raise RuntimeError("TMPDIR must be an absolute directory without symlink components")
    info = scratch.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o022
        or scratch == Path("/")
        or not os.access(scratch, os.W_OK | os.X_OK)
    ):
        raise RuntimeError("TMPDIR must be owned, writable and not writable by others")
    prefixes = {}
    for language in selected_languages():
        executable = shutil.which("php" if language == "php" else "dotnet")
        if executable is None:
            raise RuntimeError("selected " + language + " runtime is missing from PATH")
        variable = (
            "YAMORA_HTTP_REPLICA_PHP_ADAPTER"
            if language == "php"
            else "YAMORA_HTTP_REPLICA_CSHARP_DLL"
        )
        artifact = Path(os.environ.get(variable, ""))
        if not artifact.is_absolute() or not artifact.is_file() or not os.access(artifact, os.R_OK):
            raise RuntimeError(variable + " must name an absolute readable file")
        prefixes[language] = (
            [executable, "-n", str(artifact)] if language == "php" else [executable, str(artifact)]
        )
    return scratch, prefixes


class Session:
    def __init__(self, prefix, root, case):
        self.case = case
        self.proc = subprocess.Popen(
            [*prefix, "--config", str(root / "config.json"), "--root", str(root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def call(self, value):
        self.proc.stdin.write(encode(value))
        self.proc.stdin.flush()
        if not select.select([self.proc.stdout], [], [], 25)[0]:
            raise RuntimeError("adapter outside watchdog (infrastructure)")
        line = self.proc.stdout.readline(16385)
        self.case.assertTrue(line.endswith(b"\n"), "missing observation: " + repr(line))
        self.case.assertLessEqual(len(line), 16384)
        value_out = json.loads(line)
        self.case.assertEqual(set(value_out), OBS_KEYS)
        self.case.assertEqual(set(value_out["api"]), API_KEYS)
        self.case.assertEqual(value_out["schema"], OBSERVATION)
        self.case.assertEqual(value_out["seq"], value["seq"])
        self.case.assertEqual(value_out["action"], value["action"])
        self.case.assertGreaterEqual(value_out["elapsed_ns"], 0)
        return value_out

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()  # Only this test's child; every path reaps it.
        self.proc.wait(5)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            stream.close()


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch, cls.prefixes = runner_configuration()
        cls.allocation = tempfile.TemporaryDirectory(dir=scratch, prefix="http-replica-controls-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.work = Path(cls.allocation.name)
        cls.certs = cls.work / "certificates"
        cls.certs.mkdir()
        certificates(cls.certs)

    @contextlib.contextmanager
    def fixture(self, language):
        with tempfile.TemporaryDirectory(dir=self.work, prefix=language + "-") as directory:
            root = Path(directory)
            (root / "input").mkdir()
            for seq in range(1, 65):
                (root / f"call-{seq:06}").mkdir()
            for name in ("ca.pem", "client.pem", "client.key"):
                shutil.copyfile(self.certs / name, root / name)
            (root / "read.token").write_text("r" * 32)
            (root / "write.token").write_text("w" * 32)
            (root / "input/value.bin").write_bytes(SOURCE)
            (root / "input/patch.bin").write_bytes(b' { "$inc" : { "n" : 1 } }\n')
            peers = []
            try:
                for node in range(1, 4):
                    peers.append(Peer(self.certs, node))
                config = {
                    "schema": "yamora-http-replica-config/2",
                    "cluster_id": CLUSTER,
                    "voters": 3,
                    "seeds": [p.seed() for p in peers],
                    "tls": {
                        "ca_file": "ca.pem",
                        "cert_file": "client.pem",
                        "key_file": "client.key",
                    },
                    "tokens": {"read_file": "read.token", "write_file": "write.token"},
                    "timeout_ms": 15000,
                    "attempt_timeout_ms": 3000,
                }
                (root / "config.json").write_bytes(encode(config))
                yield root, config, peers
            finally:
                for peer in peers:
                    peer.close()

    @contextlib.contextmanager
    def session(self, language, root):
        session = Session(self.prefixes[language], root, self)
        try:
            yield session
        finally:
            session.close()

    def closed(self, session, seq):
        observed = session.call(command(seq, "close"))
        self.assertEqual(observed["outcome"], "closed")
        self.assertEqual(observed["elapsed_ns"], 0)
        self.assertTrue(all(v is None for v in observed["api"].values()))
        for name in (
            "error_kind",
            "sdk_request_id",
            "envelope",
            "recovery_mode",
            "recovery_handle",
        ):
            self.assertIsNone(observed[name])
        self.assertEqual(session.proc.wait(5), 0)
        self.assertEqual(session.proc.stdout.read(), b"")
        self.assertEqual(session.proc.stderr.read(), b"")

    def invalid(self, language, root, raw):
        result = subprocess.run(
            [*self.prefixes[language], "--config", str(root / "config.json"), "--root", str(root)],
            input=raw,
            capture_output=True,
            timeout=25,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(
            result.stderr, b"http replica adapter: invalid input or infrastructure failure\n"
        )

    def test_success_and_honest_exposure(self):
        for language in self.prefixes:
            with (
                self.subTest(language=language),
                self.fixture(language) as (root, _, peers),
                self.session(language, root) as session,
            ):
                for seq, method in enumerate(("PUT", "PATCH", "GET", "DELETE"), 1):
                    fields = {
                        "method": method,
                        "source_file": "input/value.bin"
                        if method == "PUT"
                        else "input/patch.bin"
                        if method == "PATCH"
                        else None,
                    }
                    if method == "PUT":
                        fields.update(if_none_match="*", request_id="1" * 32)
                    observed = session.call(command(seq, **fields))
                    self.assertEqual(observed["outcome"], "success")
                    self.assertEqual(observed["api"]["revision"], REVISION)
                    self.assertIsNone(observed["api"]["status"])
                    for key in (
                        "sdk_request_id",
                        "envelope",
                        "recovery_mode",
                        "recovery_handle",
                        "error_kind",
                    ):
                        self.assertIsNone(observed[key])
                    if method == "GET":
                        self.assertEqual((root / observed["api"]["body_file"]).read_bytes(), SOURCE)
                    else:
                        self.assertIsNone(observed["api"]["body_file"])
                    if method in ("PUT", "PATCH"):
                        self.assertEqual(observed["api"]["etag"], REVISION)
                        if language == "php":
                            self.assertEqual(
                                observed["api"]["receipt"],
                                {
                                    "status": "stored",
                                    "collection": "manifests",
                                    "document": "counter",
                                    "etag": REVISION,
                                    "revision": REVISION,
                                },
                            )
                        else:
                            self.assertIsNone(observed["api"]["receipt"])
                    if method == "DELETE":
                        self.assertIsNone(observed["api"]["etag"])
                        self.assertIsNone(observed["api"]["receipt"])
                mutations = [
                    r for p in peers for r in p.records if r[0] in ("PUT", "PATCH", "DELETE")
                ]
                self.assertEqual(mutations[0][3], SOURCE)
                self.assertEqual(mutations[0][2]["if-none-match"], "*")
                self.assertEqual(json.loads(mutations[1][3]), {"$inc": {"n": 1}})
                self.closed(session, 5)

    def test_actual_uncertainty_retains_id_conditions_and_bytes(self):
        for language in self.prefixes:
            for supplied in (None, "2" * 32):
                with (
                    self.subTest(language=language, supplied=supplied),
                    self.fixture(language) as (root, _, peers),
                    self.session(language, root) as session,
                ):
                    peers[0].bad_receipt = True
                    observed = session.call(
                        command(request_id=supplied, if_match='"' + REVISION + '"')
                    )
                    self.assertEqual(observed["outcome"], "uncertain")
                    self.assertEqual(observed["error_kind"], "protocol")
                    self.assertEqual(observed["recovery_mode"], "sdk-envelope")
                    self.assertEqual(observed["recovery_handle"], "h1")
                    identity = observed["sdk_request_id"]
                    self.assertIsInstance(identity, str)
                    self.assertRegex(identity, "^[0-9a-f]{32}$")
                    self.assertNotEqual(identity, "0" * 32)
                    if supplied:
                        self.assertEqual(identity, supplied)
                    envelope = observed["envelope"]
                    self.assertEqual(
                        set(envelope),
                        {"method", "path", "if_match", "if_none_match", "request_id", "body_file"},
                    )
                    self.assertEqual(envelope["method"], "PATCH")
                    self.assertEqual(
                        envelope["path"], "/v1/collections/manifests/documents/counter"
                    )
                    self.assertEqual(envelope["if_match"], '"' + REVISION + '"')
                    self.assertIsNone(envelope["if_none_match"])
                    self.assertEqual(envelope["request_id"], identity)
                    original = [r for p in peers for r in p.records if r[0] == "PATCH"][0]
                    self.assertEqual((root / envelope["body_file"]).read_bytes(), original[3])
                    self.assertEqual(original[2]["x-yamora-request-id"], identity)
                    # Mutating the caller's source file cannot change an SDK-owned recovery.
                    (root / "input/patch.bin").write_bytes(b'{"$inc":{"n":99}}')
                    peers[0].bad_receipt = False
                    recovered = session.call(command(2, "recover", handle="h1"))
                    self.assertEqual(recovered["outcome"], "success")
                    self.assertEqual(recovered["recovery_handle"], "h1")
                    self.assertEqual(recovered["recovery_mode"], "sdk-envelope")
                    self.assertIsNone(recovered["sdk_request_id"])
                    self.assertIsNone(recovered["envelope"])
                    self.assertEqual(recovered["api"]["revision"], REVISION)
                    replay = [r for p in peers for r in p.records if r[0] == "PATCH"][-1]
                    self.assertEqual(replay[3], original[3], "recovery changed captured SDK bytes")
                    self.assertEqual(
                        replay[2]["x-yamora-request-id"], identity, "recovery minted a new ID"
                    )
                    if language == "csharp":
                        self.assertEqual(recovered["api"]["status"], 200)
                        self.assertEqual(recovered["api"]["etag"], '"' + REVISION + '"')
                        self.assertIsNone(recovered["api"]["receipt"])
                        self.assertEqual(
                            json.loads((root / recovered["api"]["body_file"]).read_bytes())[
                                "status"
                            ],
                            "stored",
                        )
                    else:
                        self.assertIsNone(recovered["api"]["status"])
                        self.assertIsNone(recovered["api"]["body_file"])
                        self.assertEqual(recovered["api"]["receipt"]["status"], "stored")
                    # Handles survive successful recovery and never become new calls.
                    again = session.call(command(3, "recover", handle="h1"))
                    self.assertEqual(again["outcome"], "success")
                    writes = [r for p in peers for r in p.records if r[0] == "PATCH"]
                    self.assertEqual(len(writes), 3)
                    for record in writes:
                        self.assertEqual(record[3], original[3])
                        self.assertEqual(record[2]["x-yamora-request-id"], identity)
                        self.assertEqual(record[2]["if-match"], '"' + REVISION + '"')
                    self.closed(session, 4)

    def test_repeated_uncertainty_keeps_handle(self):
        for language in self.prefixes:
            with (
                self.subTest(language=language),
                self.fixture(language) as (root, _, peers),
                self.session(language, root) as session,
            ):
                peers[0].bad_receipt = True
                first = session.call(command())
                second = session.call(command(2, "recover", handle="h1"))
                self.assertEqual(second["outcome"], "uncertain")
                self.assertEqual(second["sdk_request_id"], first["sdk_request_id"])
                self.assertEqual(second["envelope"]["request_id"], first["sdk_request_id"])
                self.assertEqual(second["recovery_handle"], "h1")
                self.closed(session, 3)

    def test_php_suppressed_tls_warning_retains_session_and_recovery(self):
        with self.fixture("php") as (root, _, peers), self.session("php", root) as session:
            peers[0].bad_receipt = True
            first = session.call(command())
            self.assertEqual(first["outcome"], "uncertain")
            self.assertEqual(first["error_kind"], "protocol")
            self.assertEqual(first["recovery_handle"], "h1")
            identity = first["sdk_request_id"]
            original = [
                record for peer in peers for record in peer.records if record[0] == "PATCH"
            ][0]
            self.assertEqual(identity, original[2]["x-yamora-request-id"])
            self.assertIsNone(session.proc.poll())
            for peer in peers:
                peer.reject_tls = True
            # The failure must be an SDK observation in this same live process,
            # not an adapter exit that loses the original uncertain mutation.
            failed = session.call(command(2, "recover", handle="h1"))
            self.assertEqual(failed["outcome"], "uncertain")
            self.assertIn(failed["error_kind"], ("deadline", "transport", "status"))
            self.assertEqual(failed["sdk_request_id"], identity)
            self.assertEqual(failed["recovery_handle"], "h1")
            self.assertEqual(failed["recovery_mode"], "sdk-envelope")
            self.assertIsNone(session.proc.poll())
            self.assertTrue(
                all(peer.tls_rejections > 0 for peer in peers), "SDK did not retry configured seeds"
            )
            writes = [record for peer in peers for record in peer.records if record[0] == "PATCH"]
            self.assertEqual(len(writes), 1, "TLS rejection dispatched another HTTP mutation")
            self.assertEqual((root / failed["envelope"]["body_file"]).read_bytes(), original[3])
            for peer in peers:
                peer.reject_tls = False
                peer.bad_receipt = False
            recovered = session.call(command(3, "recover", handle="h1"))
            self.assertEqual(recovered["outcome"], "success")
            self.assertEqual(recovered["recovery_handle"], "h1")
            replay = [record for peer in peers for record in peer.records if record[0] == "PATCH"][
                -1
            ]
            self.assertEqual(replay[2]["x-yamora-request-id"], identity)
            self.assertEqual(replay[3], original[3])
            self.closed(session, 4)

    def test_php_socket_write_reset_retries_and_retains_actual_recovery(self):
        with self.fixture("php") as (root, _, peers), self.session("php", root) as session:
            source = SOURCE + b"#" + b"x" * (131072 - len(SOURCE) - 2) + b"\n"
            (root / "input/value.bin").write_bytes(source)
            peers[0].reset_write = True
            peers[1].status = 403
            peers[2].status = 403
            first = session.call(command(method="PUT", source_file="input/value.bin"))
            self.assertEqual(first["outcome"], "uncertain")
            self.assertEqual(first["error_kind"], "status")
            self.assertEqual(first["api"]["status"], 403)
            self.assertEqual(first["recovery_handle"], "h1")
            self.assertIsNone(session.proc.poll())
            self.assertEqual(peers[0].write_resets, 1)
            attempt = peers[0].attempted_writes[0]
            identity = first["sdk_request_id"]
            self.assertEqual(attempt[2]["x-yamora-request-id"], identity)
            retry = [record for peer in peers[1:] for record in peer.records if record[0] == "PUT"]
            self.assertEqual(len(retry), 1, "SDK did not retry the reset mutation")
            self.assertEqual(retry[0][2]["x-yamora-request-id"], identity)
            self.assertEqual(retry[0][3], source)
            self.assertEqual((root / first["envelope"]["body_file"]).read_bytes(), source)
            (root / "input/value.bin").write_bytes(b"n: 99\n")
            for peer in peers:
                peer.reset_write = False
                peer.status = None
            recovered = session.call(command(2, "recover", handle="h1"))
            self.assertEqual(recovered["outcome"], "success")
            self.assertEqual(recovered["recovery_handle"], "h1")
            replay = [record for peer in peers for record in peer.records if record[0] == "PUT"][-1]
            self.assertEqual(replay[2]["x-yamora-request-id"], identity)
            self.assertEqual(replay[3], source)
            self.closed(session, 3)

    def test_php_unsuppressed_file_warning_remains_fatal(self):
        with self.fixture("php") as (root, _, peers):
            output = root / "call-000001/body.bin"
            output.write_bytes(b"preserve existing output")
            # Exclusive output creation emits an unsuppressed fopen warning.
            # It must remain a fixed-diagnostic failure, never overwrite data.
            self.invalid("php", root, encode(command(method="GET", source_file=None)))
            self.assertEqual(output.read_bytes(), b"preserve existing output")
            self.assertTrue(
                any(
                    record[1].endswith("/documents/counter")
                    for peer in peers
                    for record in peer.records
                )
            )

    def test_delete_envelope_and_recovery_exposure(self):
        for language in self.prefixes:
            with (
                self.subTest(language=language),
                self.fixture(language) as (root, _, peers),
                self.session(language, root) as session,
            ):
                # Wrong success status makes this an actual SDK uncertain delete.
                peers[0].status = 200
                first = session.call(command(method="DELETE", source_file=None))
                self.assertEqual(first["outcome"], "uncertain")
                body_file = first["envelope"]["body_file"]
                if language == "csharp":
                    self.assertIsNone(body_file)
                else:
                    self.assertEqual((root / body_file).read_bytes(), b"")
                peers[0].status = None
                recovered = session.call(command(2, "recover", handle="h1"))
                self.assertEqual(recovered["outcome"], "success")
                self.assertEqual(recovered["api"]["revision"], REVISION)
                self.assertIsNone(recovered["api"]["receipt"])
                if language == "csharp":
                    self.assertEqual(recovered["api"]["status"], 204)
                    self.assertEqual((root / recovered["api"]["body_file"]).read_bytes(), b"")
                else:
                    self.assertIsNone(recovered["api"]["status"])
                    self.assertIsNone(recovered["api"]["body_file"])
                self.closed(session, 3)

    def test_certain_http_error_and_redacted_peer_text(self):
        for language in self.prefixes:
            with (
                self.subTest(language=language),
                self.fixture(language) as (root, _, peers),
                self.session(language, root) as session,
            ):
                peers[0].status = 409
                observed = session.call(command(request_id="3" * 32))
                self.assertEqual(observed["outcome"], "status")
                self.assertEqual(observed["api"]["status"], 409)
                for key in ("sdk_request_id", "envelope", "recovery_mode", "recovery_handle"):
                    self.assertIsNone(observed[key])
                self.assertNotIn("SYNTHETIC-PEER-SECRET", json.dumps(observed))
                self.closed(session, 2)

    def test_invalid_json_protocol_and_types_before_dispatch(self):
        base = encode(command())
        invalid = [
            b"",
            base[:-1],
            b"{}\n",
            b"x\n",
            b"\xff\n",
            b" " * 16384 + b"\n",
            base.replace(b'"seq":1', b'"seq":1,"seq":1'),
            base.replace(b'"seq":1', b'"seq":1,"s\\u0065q":1'),
            base.replace(b'"seq":1', b'"seq":NaN'),
            base.replace(b'"seq":1', b'"seq":1e400'),
            encode(command(seq=2)),
            encode(command(extra="SYNTHETIC-PEER-SECRET")),
            encode(command(request_id="0" * 32)),
            encode(command(request_id=7)),
            encode(command(if_match=REVISION)),
            encode(command(if_none_match="*")),
            encode(command(method="PUT", if_match='"' + REVISION + '"', if_none_match="*")),
            encode(command(method="GET", source_file=None, request_id="1" * 32)),
            encode(command(collection="yamldb-system")),
            encode(command(method="POST")),
            encode(command(1, "recover", handle="h1")),
            encode(command(1, "close", extra=1)),
            b'{"a":' + b"[" * 13 + b"0" + b"]" * 13 + b"}\n",
        ]
        for language in self.prefixes:
            with self.fixture(language) as (root, _, peers):
                for index, raw in enumerate(invalid):
                    with self.subTest(language=language, index=index):
                        self.invalid(language, root, raw)
                self.assertFalse(any(p.records for p in peers))

    def test_config_file_bounds_before_dispatch(self):
        for language in self.prefixes:
            with self.fixture(language) as (root, _, peers):
                for name in ("ca.pem", "client.pem", "client.key", "read.token", "write.token"):
                    path = root / name
                    original = path.read_bytes()
                    bound = 512 if name.endswith(".token") else 16384
                    path.write_bytes(original + b"\n" * (bound + 1 - len(original)))
                    with self.subTest(language=language, name=name):
                        self.invalid(language, root, encode(command(1, "close")))
                    path.write_bytes(original)
                self.assertFalse(any(p.records for p in peers))

    def test_jsonl_carriage_returns_rejected_before_dispatch(self):
        base = encode(command())
        malformed = [base[:-1] + b"\r\n", b"\r" + base, base.replace(b'"seq":1', b'\r"seq":1')]
        for language in self.prefixes:
            with self.fixture(language) as (root, _, peers):
                for index, raw in enumerate(malformed):
                    with self.subTest(language=language, index=index):
                        self.invalid(language, root, raw)
                with self.subTest(language=language, check="no traffic"):
                    self.assertFalse(any(p.records for p in peers))

    def test_source_path_file_size_and_patch_validation(self):
        for language in self.prefixes:
            with self.fixture(language) as (root, _, peers):
                for source in (
                    "../config.json",
                    "/etc/passwd",
                    "input/../config.json",
                    "input/missing.bin",
                    "input/a.bin/evil",
                ):
                    with self.subTest(language=language, source=source):
                        self.invalid(language, root, encode(command(source_file=source)))
                path = root / "input/patch.bin"
                for raw in (
                    b"",
                    b"x" * 131073,
                    b"\xff",
                    b'{"$inc":{"n":2}}',
                    b'{"$inc":{"n":1,"n":1}}',
                    b'{"$inc":{"n":1},"$set":{"a":2}}',
                ):
                    path.write_bytes(raw)
                    with self.subTest(language=language, raw_kind=len(raw)):
                        self.invalid(language, root, encode(command()))
                path.unlink()
                path.symlink_to(root / "input/value.bin")
                self.invalid(language, root, encode(command()))
                path.unlink()
                path.mkdir()
                self.invalid(language, root, encode(command()))
                path.rmdir()
                os.mkfifo(path)
                self.invalid(language, root, encode(command()))
                self.assertFalse(any(p.records for p in peers))

    def test_config_rejects_untrusted_binding_and_paths(self):
        for language in self.prefixes:
            with self.fixture(language) as (root, config, peers):
                configurations = []
                for path, value in (
                    ("schema", "other"),
                    ("voters", 5),
                    ("cluster_id", "0" * 32),
                    ("timeout_ms", 15001),
                    ("attempt_timeout_ms", 3001),
                ):
                    c = copy.deepcopy(config)
                    c[path] = value
                    configurations.append(c)
                for field, value in (
                    ("host", "localhost"),
                    ("host", "8.8.8.8"),
                    ("port", 8000),
                    ("node", 2),
                ):
                    c = copy.deepcopy(config)
                    c["seeds"][0][field] = value
                    configurations.append(c)
                c = copy.deepcopy(config)
                c["tls"]["key_file"] = "../client.key"
                configurations.append(c)
                for index, c in enumerate(configurations):
                    with self.subTest(language=language, index=index):
                        (root / "config.json").write_bytes(encode(c))
                        self.invalid(language, root, encode(command(1, "close")))
                (root / "config.json").write_bytes(encode(config))
                for name in (
                    "config.json",
                    "ca.pem",
                    "client.pem",
                    "client.key",
                    "read.token",
                    "write.token",
                ):
                    original = root / name
                    moved = root / (name + ".saved")
                    original.rename(moved)
                    original.symlink_to(moved)
                    with self.subTest(language=language, symlink=name):
                        self.invalid(language, root, encode(command(1, "close")))
                    original.unlink()
                    moved.rename(original)
                self.assertFalse(any(p.records for p in peers))

    def test_output_symlink_cannot_escape(self):
        for language in self.prefixes:
            with self.fixture(language) as (root, _, _):
                outside = root / "preserve.bin"
                outside.write_bytes(b"preserve")
                (root / "call-000001/body.bin").symlink_to(outside)
                self.invalid(language, root, encode(command(method="GET", source_file=None)))
                self.assertEqual(outside.read_bytes(), b"preserve")

    def test_clean_close_eof_and_interruption(self):
        for language in self.prefixes:
            with self.fixture(language) as (root, _, _):
                with self.session(language, root) as session:
                    self.closed(session, 1)
                self.invalid(language, root, b"")
                with self.session(language, root) as session:
                    # A completed call followed by EOF remains incomplete.
                    session.call(command(method="GET", source_file=None))
                    session.proc.stdin.close()
                    self.assertNotEqual(session.proc.wait(5), 0)
                    self.assertEqual(session.proc.stdout.read(), b"")
                    self.assertLessEqual(len(session.proc.stderr.read()), 16384)
                with self.session(language, root) as session:
                    session.call(command())
                    session.proc.send_signal(signal.SIGTERM)
                    self.assertNotEqual(session.proc.wait(5), 0)
                    self.assertLessEqual(len(session.proc.stderr.read()), 16384)

    def test_exact_line_and_file_bounds(self):
        for language in self.prefixes:
            with self.subTest(language=language), self.fixture(language) as (root, _, peers):
                raw = encode(command(1, "close"))
                raw = raw[:-1] + b" " * (16384 - len(raw)) + b"\n"
                result = subprocess.run(
                    [
                        *self.prefixes[language],
                        "--config",
                        str(root / "config.json"),
                        "--root",
                        str(root),
                    ],
                    input=raw,
                    capture_output=True,
                    timeout=25,
                )
                self.assertEqual(len(raw), 16384)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["outcome"], "closed")
                self.assertEqual(result.stderr, b"")
                boundary = SOURCE + b"#" + b"x" * (131072 - len(SOURCE) - 2) + b"\n"
                self.assertEqual(len(boundary), 131072)
                (root / "input/value.bin").write_bytes(boundary)
                peers[0].body_override = boundary
                with self.session(language, root) as session:
                    stored = session.call(command(method="PUT", source_file="input/value.bin"))
                    self.assertEqual(stored["outcome"], "success")
                    fetched = session.call(command(2, method="GET", source_file=None))
                    self.assertEqual(fetched["outcome"], "success")
                    self.assertEqual((root / fetched["api"]["body_file"]).read_bytes(), boundary)
                    peers[0].body_override = boundary + b"x"
                    rejected = session.call(command(3, method="GET", source_file=None))
                    self.assertEqual(rejected["outcome"], "protocol")
                    self.assertIsNone(rejected["api"]["body_file"])
                    self.closed(session, 4)

    def test_symlink_components_cannot_escape(self):
        for language in self.prefixes:
            with self.fixture(language) as (root, _, peers):
                saved_input = root / "saved-input"
                (root / "input").rename(saved_input)
                (root / "input").symlink_to(saved_input, target_is_directory=True)
                self.invalid(language, root, encode(command()))
                (root / "input").unlink()
                saved_input.rename(root / "input")
                self.assertFalse(any(p.records for p in peers))
                saved_output = root / "saved-output"
                (root / "call-000001").rename(saved_output)
                (root / "call-000001").symlink_to(saved_output, target_is_directory=True)
                self.invalid(language, root, encode(command(method="GET", source_file=None)))
                self.assertEqual(list(saved_output.iterdir()), [])

    def test_command_and_handle_count_bounds(self):
        for language in self.prefixes:
            with (
                self.fixture(language) as (root, _, peers),
                self.session(language, root) as session,
            ):
                peers[0].bad_receipt = True
                for seq in range(1, 17):
                    observed = session.call(command(seq))
                    self.assertEqual(observed["recovery_handle"], "h" + str(seq))
                writes_before = len([r for p in peers for r in p.records if r[0] == "PATCH"])
                session.proc.stdin.write(encode(command(17)))
                session.proc.stdin.flush()
                self.assertNotEqual(session.proc.wait(5), 0)
                self.assertEqual(session.proc.stdout.read(), b"")
                self.assertEqual(
                    len([r for p in peers for r in p.records if r[0] == "PATCH"]), writes_before
                )
            with self.fixture(language) as (root, _, _), self.session(language, root) as session:
                for seq in range(1, 65):
                    session.call(command(seq, method="GET", source_file=None))
                self.assertNotEqual(session.proc.wait(5), 0)
                self.assertEqual(session.proc.stdout.read(), b"")


def load_tests(loader, _tests, _pattern):
    # Exclude PHP-only controls from a C# foundation instead of skipping them or
    # requiring another foundation's runtime. All 15 shared controls still run.
    languages = selected_languages()
    return unittest.TestSuite(
        AdapterTests(name)
        for name in loader.getTestCaseNames(AdapterTests)
        if "php" in languages or not name.startswith("test_php_")
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
