"""Exercise CRL options through real daemon HTTP and replica-set startup."""

import http.client
import json
import re
import select
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.tests import test_tls_revocation as revocation
from yamora.tests.test_document_api import BINARY


class NativeTlsRevocationDaemonTests(unittest.TestCase):
    # Reuse the synthetic PKI builder without inheriting/rerunning the core suite.
    openssl = classmethod(revocation.NativeTlsRevocationTests.openssl.__func__)
    leaf = classmethod(revocation.NativeTlsRevocationTests.leaf.__func__)
    crl = classmethod(revocation.NativeTlsRevocationTests.crl.__func__)

    @classmethod
    def setUpClass(cls):
        revocation.NativeTlsRevocationTests.setUpClass.__func__(cls)
        cls.daemon = BINARY
        if not cls.daemon.is_file():
            build = cls.fixtures / "daemon-build"
            result = subprocess.run(
                [
                    "make",
                    "-C",
                    str(Path(__file__).resolve().parents[1]),
                    "-j2",
                    f"BUILD_DIR={build}",
                    "all",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            cls.daemon = build / "yamora"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=runtime_root())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        initialized = subprocess.run(
            [str(self.daemon), "--data-dir", str(self.data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        self.read, self.write = self.root / "read.token", self.root / "write.token"
        for path, token in ((self.read, "r" * 32), (self.write, "w" * 32)):
            path.write_text(token)
            path.chmod(0o600)
        self.active = self.root / "current.crl"
        self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())

    def arguments(self, *, crl=None, data=None, extra=(), public_crl=True):
        arguments = [
            str(self.daemon),
            "--data-dir",
            str(data or self.data),
            "--port",
            "0",
            "--workers",
            "2",
            "--io-timeout-ms",
            "1000",
            "--auth-token-file",
            str(self.read),
            "--write-auth-token-file",
            str(self.write),
            "--tls-cert-file",
            str(self.fixtures / "server.pem"),
            "--tls-key-file",
            str(self.fixtures / "server.key"),
            "--tls-client-ca-file",
            str(self.fixtures / "trusted.pem"),
            "--tls-crl-file",
            str(self.active if crl is None else crl),
            *map(str, extra),
        ]
        return arguments if public_crl else self.without(arguments, "--tls-crl-file")

    @staticmethod
    def without(arguments, *options):
        out = list(arguments)
        for option in options:
            index = out.index(option)
            del out[index : index + 2]
        return out

    def start(self, **kwargs):
        process = subprocess.Popen(
            self.arguments(**kwargs), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        def cleanup():
            if process.poll() is not None and process.stdout.closed:
                return
            if process.poll() is None:
                process.terminate()
            _, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, error)

        if not select.select([process.stdout], [], [], 15)[0]:
            process.kill()
            _, error = process.communicate(timeout=5)
            self.fail(f"daemon startup stalled: {error}")
        line = process.stdout.readline()
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        if not match:
            _, error = process.communicate(timeout=5)
            self.fail(f"daemon rejected CRL startup: {error}")
        self.addCleanup(cleanup)
        return process, int(match.group(1))

    def request(
        self, port, *, identity="client", method="GET", path="/readyz", body=b"", token="r" * 32
    ):
        context = ssl.create_default_context(cafile=str(self.fixtures / "trusted.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(
            self.fixtures / f"{identity}.pem", self.fixtures / f"{identity}.key"
        )
        auth = f"Authorization: Bearer {token}\r\n" if token else ""
        headers = (
            f"{method} {path} HTTP/1.1\r\nHost: server.test\r\n{auth}"
            f"Content-Type: application/yaml\r\nContent-Length: {len(body)}\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="server.test") as secured:
                self.assertEqual(secured.version(), "TLSv1.3")
                secured.sendall(headers.encode() + body)
                response = http.client.HTTPResponse(secured)
                response.begin()
                return response.status, response.read()

    def test_public_crl_accepts_valid_and_blocks_revoked_before_http_mutation(self):
        _, port = self.start()
        self.assertEqual(self.request(port)[0], 200)
        self.assertEqual(self.request(port, token=None)[0], 401)
        path = "/v1/collections/manifests/documents/one"
        original = b"# exact source\r\nvalue: original # retained\r\n"
        self.assertEqual(
            self.request(port, method="PUT", path=path, body=original, token="w" * 32)[0], 201
        )
        with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
            self.request(
                port,
                identity="revoked-client",
                method="PUT",
                path=path,
                body=b"value: forbidden\n",
                token="w" * 32,
            )
        self.assertEqual(self.request(port, path=path), (200, original))

    def test_public_crl_missing_invalid_or_incomplete_options_refuse_startup(self):
        invalid = self.root / "invalid.crl"
        invalid.write_text("invalid signed CRL")
        args = self.arguments()
        cases = [
            self.without(args, "--tls-client-ca-file"),
            self.without(args, "--tls-client-ca-file", "--tls-cert-file", "--tls-key-file"),
            self.without(args, "--tls-crl-file") + ["--tls-crl-file"],
            self.arguments(crl=""),
            self.arguments(crl=self.root / "missing.crl"),
            self.arguments(crl=invalid),
            *(
                self.arguments(crl=self.fixtures / f"{name}.crl")
                for name in ("expired", "future", "foreign", "impostor")
            ),
        ]
        before = (self.data / ".yamora-disk").read_bytes()
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run(arguments, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result)
                self.assertNotIn(b"listening on", result.stdout)
                self.assertEqual((self.data / ".yamora-disk").read_bytes(), before)

    def test_public_sighup_publishes_crl_and_retains_verified_snapshot_on_failure(self):
        self.active.write_bytes((self.fixtures / "clear.crl").read_bytes())
        process, port = self.start()
        self.assertEqual(self.request(port, identity="revoked-client")[0], 200)
        self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())
        process.send_signal(signal.SIGHUP)
        end = time.monotonic() + 5
        while True:
            try:
                self.request(port, identity="revoked-client")
            except (ssl.SSLError, OSError, http.client.HTTPException):
                break
            self.assertLess(time.monotonic(), end, "SIGHUP did not install CRL")
            time.sleep(0.01)
        self.assertEqual(self.request(port)[0], 200)
        self.active.write_text("broken replacement")
        process.send_signal(signal.SIGHUP)
        self.assertTrue(select.select([process.stderr], [], [], 5)[0], "reload result missing")
        self.assertIn("reload rejected", process.stderr.readline())
        self.assertEqual(self.request(port)[0], 200)
        with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
            self.request(port, identity="revoked-client")

    def cluster(self, crl):
        data, journal, config = (
            self.root / name for name in ("peer-data", "journal", "cluster.json")
        )
        data.mkdir(exist_ok=True)
        journal.mkdir(exist_ok=True)
        with socket.socket() as first, socket.socket() as second, socket.socket() as third:
            sockets = (first, second, third)
            for item in sockets:
                item.bind(("127.0.0.1", 0))
            ports = [item.getsockname()[1] for item in sockets]
        tls = {
            "cert_file": str(self.fixtures / "server.pem"),
            "key_file": str(self.fixtures / "server.key"),
            "ca_file": str(self.fixtures / "trusted.pem"),
        }
        if crl is not None:
            tls["crl_file"] = crl
        spec = {
            "cluster": "01020304000000000000000000000000",
            "node": 1,
            "journal_dir": str(journal),
            "peer_tls": tls,
            "peers": [
                {"id": i + 1, "name": name, "address": "127.0.0.1", "port": ports[i]}
                for i, name in enumerate(("server.test", "client.test", "third.test"))
            ],
        }
        config.write_text(json.dumps(spec))
        config.chmod(0o600)
        return data, journal, config, ports[0]

    def test_peer_crl_optional_config_accepts_valid_path(self):
        for crl in (str(self.active), None):
            # Each cluster owns distinct disposable roots, never an existing database.
            with tempfile.TemporaryDirectory(dir=self.root) as cluster_root:
                old = self.root
                try:
                    self.root = Path(cluster_root)
                    data, _, config, _ = self.cluster(crl)
                    process, port = self.start(
                        data=data, public_crl=False, extra=("--cluster-config-file", config)
                    )
                    self.assertEqual(self.request(port, path="/healthz")[0], 200)
                    process.terminate()
                    _, error = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 0, error)
                finally:
                    self.root = old

    def test_peer_crl_invalid_types_paths_and_snapshots_reject_before_storage(self):
        missing = self.root / "missing-peer.crl"
        for crl in (
            None,
            "relative.crl",
            "",
            1,
            True,
            [],
            {},
            "/bad\npath",
            "/" + "x" * 4097,
            str(missing),
            str(self.fixtures / "expired.crl"),
            str(self.fixtures / "foreign.crl"),
        ):
            with self.subTest(crl=crl):
                data, journal, config, _ = self.cluster(crl)
                if crl is None:
                    spec = json.loads(config.read_text())
                    spec["peer_tls"]["crl_file"] = None
                    config.write_text(json.dumps(spec))
                result = subprocess.run(
                    self.arguments(data=data, extra=("--cluster-config-file", config)),
                    capture_output=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0, result)
                self.assertNotIn(b"listening on", result.stdout)
                self.assertEqual(list(data.iterdir()), [])
                self.assertEqual(list(journal.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
