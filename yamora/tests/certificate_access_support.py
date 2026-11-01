"""Shared synthetic PKI and real-daemon adapters for certificate acceptance.

Set YAMLDB_BUILD_DIR before importing the suite. A missing daemon is an error;
these adapters never build a daemon or substitute a mocked authorization path.
"""

import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import time

from yamora.tests import test_binary_runtime as binary_fixture
from yamora.tests import test_tls as tls_fixture
from yamora.tests.binary_runtime_support import WireClient
from yamora.tests.test_document_api import BINARY


class CertificateIdentityGate:
    """One test-only callback pause before borrowed identity is consumed."""

    def __init__(self, nth=1):
        if not 1 <= nth <= 128:
            raise ValueError("invalid certificate callback call number")
        self.nth = nth
        self.parent, self.child = socket.socketpair()

    def environment(self):
        return {
            "YAMORA_CERTIFICATE_GATE_FD": str(self.child.fileno()),
            "YAMORA_CERTIFICATE_GATE_NTH": str(self.nth),
        }

    def descriptors(self):
        return (self.child.fileno(),)

    def child_started(self):
        self.child.close()

    def exact(self, size):
        deadline, result = time.monotonic() + 10, bytearray()
        while len(result) < size:
            self.parent.settimeout(WireClient.remaining(deadline))
            part = self.parent.recv(size - len(result))
            if not part:
                raise RuntimeError("certificate callback gate ended before its observation")
            result.extend(part)
        return bytes(result)

    def paused(self):
        observed = struct.unpack(">cI", self.exact(5))
        if observed != (b"P", self.nth):
            raise RuntimeError("certificate callback did not pause before identity consumption")

    def resume(self):
        self.parent.settimeout(5)
        self.parent.sendall(b"R")

    def completed(self):
        event, status, revision = struct.unpack(">cH16s", self.exact(19))
        if (
            event != b"D"
            or not 200 <= status <= 599
            or any(byte not in b"0123456789abcdef" for byte in revision)
        ):
            raise RuntimeError("invalid certificate callback completion observation")
        return status, revision

    def close(self):
        self.parent.close()
        self.child.close()


class CertificateAccessSupport:
    """Reuse lifecycle methods without inheriting either fixture's tests."""

    context = tls_fixture.NativeTlsTests.context
    rotate = tls_fixture.NativeTlsTests.rotate
    arguments = tls_fixture.NativeTlsTests.arguments
    start_binary = binary_fixture.BinaryRuntimeTests.start_binary

    @staticmethod
    def openssl(*arguments):
        return subprocess.run(
            ["/usr/bin/openssl", *map(str, arguments)],
            check=True,
            capture_output=True,
            timeout=15,
        )

    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
            raise AssertionError(f"required native daemon is absent: {BINARY}")
        tls_fixture.NativeTlsTests.setUpClass.__func__(cls)
        for serial, name in enumerate(
            ("writer", "same-cn", "renewed", "node1", "node2", "node3"), 20
        ):
            cls.leaf(name, serial, same_key="client" if name == "renewed" else None)

    @classmethod
    def leaf(cls, name, serial, *, same_key=None):
        key, csr, cert, ext = [
            cls.certificates / f"{name}.{suffix}" for suffix in ("key", "csr", "pem", "ext")
        ]
        if same_key:
            shutil.copyfile(cls.certificates / f"{same_key}.key", key)
        else:
            cls.openssl(
                "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key
            )
        # Same CN and SAN deliberately confer no application identity.
        cls.openssl("req", "-new", "-key", key, "-out", csr, "-subj", "/CN=client")
        san = f"DNS:{name}.test" if name.startswith("node") else "IP:127.0.0.1"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage=clientAuth,serverAuth\nsubjectAltName={san}\n"
        )
        cls.openssl(
            "x509",
            "-req",
            "-in",
            csr,
            "-CA",
            cls.certificates / "trusted.pem",
            "-CAkey",
            cls.certificates / "trusted.key",
            "-set_serial",
            serial,
            "-days",
            "1",
            "-extfile",
            ext,
            "-out",
            cert,
        )
        key.chmod(0o600)

    @classmethod
    def pin(cls, name):
        der = ssl.PEM_cert_to_DER_cert((cls.certificates / f"{name}.pem").read_text())
        return hashlib.sha256(der).hexdigest()

    def setUp(self):
        tls_fixture.NativeTlsTests.setUp(self)
        self.policy = self.root / "access.json"
        self.scoped = self.root / "scoped.token"
        self.scoped.write_text("synthetic-certificate-reader-bearer-credential")
        self.scoped.chmod(0o600)
        self.value = self.policy_value()
        self.save_policy()

    def policy_value(self):
        return {
            "version": 2,
            "roles": {
                "reader": {"read": ["allowed", "empty"], "write": []},
                "writer": {"read": ["allowed", "empty"], "write": ["allowed", "empty"]},
            },
            "principals": {
                "reader": {"roles": ["reader"], "tls_client_sha256": [self.pin("client")]},
                "writer": {"roles": ["writer"], "tls_client_sha256": [self.pin("writer")]},
                "bearer": {"roles": ["reader"], "token_file": str(self.scoped)},
            },
        }

    def save_policy(self):
        self.policy.write_text(json.dumps(self.value))
        self.policy.chmod(0o600)

    def start_access(self, **kwargs):
        extra = kwargs.pop("extra", ())
        return self.start_binary(
            mtls=True,
            extra=("--access-policy-file", str(self.policy), "--workers", "4", *extra),
            io_timeout=15000,
            **kwargs,
        )

    def https(
        self,
        port,
        method,
        target,
        body=None,
        *,
        identity="client",
        token=None,
        value=None,
        headers=None,
    ):
        outgoing = dict(headers or {})
        if token is not None:
            outgoing["Authorization"] = "Bearer " + token
        if value is not None:
            body = json.dumps(value).encode()
            outgoing["Content-Type"] = "application/json"
        elif body is not None:
            outgoing["Content-Type"] = "application/yaml"
        connection = http.client.HTTPSConnection(
            "127.0.0.1", port, context=self.context(identity), timeout=20
        )
        try:
            connection.request(method, target, body, outgoing)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def wire(self, port, identity="client"):
        return WireClient(port, self.context(identity), timeout=20)

    def seed(self, port):
        for collection in ("allowed", "private"):
            result = self.https(
                port, "PUT", f"/v1/collections/{collection}/documents/item", SOURCE, token="w" * 32
            )
            self.assertEqual(result[0], 201, result)

    def revision(self, port):
        result = self.https(port, "GET", "/readyz", token="r" * 32)
        self.assertEqual(result[0], 200, result)
        return result[1]["X-YamlDB-Revision"]

    def stats(self, port):
        result = self.https(port, "GET", "/v1/stats", token="r" * 32)
        self.assertEqual(result[0], 200, result)
        return json.loads(result[2])

    def assert_unchanged(self, port, revision):
        self.assertEqual(self.revision(port), revision)
        for collection in ("allowed", "private"):
            result = self.https(
                port, "GET", f"/v1/collections/{collection}/documents/item", token="r" * 32
            )
            self.assertEqual((result[0], result[2]), (200, SOURCE))
        self.assertEqual(self.stats(port)["large_body_bytes"], 0)

    def stop_access(self, process):
        # The aliased fixture independently checks each owned child's exit and
        # sanitizer diagnostics in its registered cleanup, including restarts.
        process.terminate()
        process.wait(timeout=15)
        self.assertEqual(process.returncode, 0)

    def peer(self, port, *, binary=False, identity="client"):
        if binary:
            with self.wire(port, identity) as client:
                return client.socket.getpeercert(binary_form=True)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with self.context(identity).wrap_socket(raw, server_hostname="127.0.0.1") as channel:
                # Complete application IO too: TLS 1.3 client-auth rejection
                # can arrive after the client considers its handshake done.
                channel.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = http.client.HTTPResponse(channel)
                response.begin()
                self.assertEqual(response.status, 200)
                response.read()
                return channel.getpeercert(binary_form=True)

    def await_replacement(self, http_port, binary_port, *, identity="client"):
        expected = ssl.PEM_cert_to_DER_cert((self.certificates / "rotated.pem").read_text())
        for port, binary in ((http_port, False), (binary_port, True)):
            deadline = time.monotonic() + 5
            while True:
                try:
                    observed = self.peer(port, binary=binary, identity=identity)
                except (ssl.SSLError, ConnectionError, http.client.HTTPException):
                    # The replacement client can be untrusted by the context
                    # preceding SIGHUP. Only a positive new-context witness
                    # permits the caller to make post-reload denial assertions.
                    observed = None
                if observed == expected:
                    break
                self.assertLess(time.monotonic(), deadline, "TLS replacement was not published")
                time.sleep(0.02)

    def make_crls(self):
        database = self.root / "ca-index"
        database.write_text("")
        config = self.root / "ca.cnf"
        config.write_text(
            "[ca]\ndefault_ca=local\n[local]\n"
            f"database={database}\ncertificate={self.certificates}/trusted.pem\n"
            f"private_key={self.certificates}/trusted.key\n"
            "default_md=sha256\ndefault_crl_days=1\ncrl_extensions=crl\n"
            "[crl]\nauthorityKeyIdentifier=keyid:always\n"
        )
        clear, revoked = self.root / "clear.crl", self.root / "revoked.crl"
        self.openssl("ca", "-batch", "-config", config, "-gencrl", "-out", clear)
        self.openssl("ca", "-batch", "-config", config, "-revoke", self.certificates / "client.pem")
        self.openssl("ca", "-batch", "-config", config, "-gencrl", "-out", revoked)
        return clear, revoked


SOURCE = b"# certificate access\r\nkey: 01 # exact source\r\n"
TARGET = "/v1/collections/allowed/documents/item"
