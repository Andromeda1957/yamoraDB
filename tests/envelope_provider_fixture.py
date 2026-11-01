"""Loopback TLS protocol fixture, never a claim of real AWS/Vault qualification."""

import base64
import contextlib
import datetime
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

AWS_ID = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(text):
    return base64.b64decode(text, validate=True)


def certificate(root, name="localhost"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = root / (name + ".pem"), root / (name + ".key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path


@contextlib.contextmanager
def service(cert_path, key_path, kind, failure=""):
    """An independent AESGCM implementation enforces protocol context binding.

    Plaintext keys, bodies, authorization and cipher blobs are never logged.
    Requests are recorded as (operation, context_digest) only for assertions.
    """
    keks = {version: AESGCM.generate_key(bit_length=256) for version in (1, 2)}
    calls = []
    problems = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            pass

        def reply(self, status, value):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                self.connection.settimeout(2)
                if self.headers.get("X-Fixture-Authorization") != "synthetic-only":
                    raise ValueError("fixture authorization missing")
                content_type = "application/x-amz-json-1.1" if kind == "aws" else "application/json"
                if self.headers.get("Content-Type") != content_type:
                    raise ValueError("provider content type mismatch")
                n = int(self.headers["Content-Length"])
                if not 0 < n <= 32768:
                    raise ValueError("unbounded request")
                request = json.loads(self.rfile.read(n))
                if kind == "aws":
                    operation = self.headers["X-Amz-Target"]
                    if self.path != "/" or operation not in (
                        "TrentService.Encrypt",
                        "TrentService.Decrypt",
                    ):
                        raise ValueError("invalid KMS endpoint/target")
                    encrypt = operation.endswith(".Encrypt")
                    expected = {
                        "KeyId",
                        "EncryptionAlgorithm",
                        "EncryptionContext",
                        "Plaintext" if encrypt else "CiphertextBlob",
                    }
                    if (
                        set(request) != expected
                        or request["KeyId"] != AWS_ID
                        or request["EncryptionAlgorithm"] != "SYMMETRIC_DEFAULT"
                        or set(request["EncryptionContext"]) != {"yamora-envelope-v1"}
                    ):
                        raise ValueError("KMS binding omitted")
                    binding = request["EncryptionContext"]["yamora-envelope-v1"]
                    context = bytes.fromhex(binding)
                    if binding != context.hex() or len(context) != 32:
                        raise ValueError("invalid KMS context")
                    payload = decode(request["Plaintext" if encrypt else "CiphertextBlob"])
                    version = 1
                else:
                    encrypt = self.path == "/v1/transit/encrypt/yamora-test"
                    if not encrypt and self.path != "/v1/transit/decrypt/yamora-test":
                        raise ValueError("invalid transit endpoint")
                    expected = (
                        {"plaintext", "associated_data", "key_version"}
                        if encrypt
                        else {"ciphertext", "associated_data"}
                    )
                    if set(request) != expected or (encrypt and request["key_version"] not in keks):
                        raise ValueError("transit version/binding omitted")
                    context = decode(request["associated_data"])
                    if len(context) != 32:
                        raise ValueError("invalid transit context")
                    if encrypt:
                        version = request["key_version"]
                        payload = decode(request["plaintext"])
                    else:
                        parts = request["ciphertext"].split(":", 2)
                        if (
                            len(parts) != 3
                            or parts[:1] != ["vault"]
                            or parts[1] not in ("v1", "v2")
                        ):
                            raise ValueError("invalid transit version")
                        version = int(parts[1][1:])
                        payload = decode(parts[2])
                calls.append(("encrypt" if encrypt else "decrypt", context.hex()))
                active = not failure.startswith("decrypt-") or not encrypt
                mutation = failure.removeprefix("decrypt-") if active else ""
                if mutation == "denied":
                    return self.reply(403, {"errors": ["fixture denied"]})
                if mutation == "unavailable":
                    return self.reply(503, {"errors": ["fixture unavailable"]})
                if mutation == "redirect":
                    return self.reply(307, {})
                if mutation == "oversize":
                    return self.reply(200, b" " * 32769)
                if mutation == "malformed":
                    return self.reply(200, b'{"Plaintext":"secret-data-key",')
                try:
                    if encrypt:
                        if len(payload) != 32:
                            raise ValueError("wrong DEK size")
                        nonce = os.urandom(12)
                        result = nonce + AESGCM(keks[version]).encrypt(nonce, payload, context)
                    else:
                        result = AESGCM(keks[version]).decrypt(payload[:12], payload[12:], context)
                except Exception:
                    return self.reply(400, {"errors": ["fixture authentication rejected"]})
                if not encrypt and mutation == "wrong-key":
                    result = os.urandom(32)
                if kind == "aws":
                    response = {
                        "KeyId": AWS_ID,
                        "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                        "CiphertextBlob" if encrypt else "Plaintext": encode(result),
                    }
                    if mutation == "key-id":
                        response["KeyId"] = AWS_ID + "-wrong"
                    if mutation == "algorithm":
                        response["EncryptionAlgorithm"] = "RSAES_OAEP_SHA_256"
                    if mutation == "duplicate":
                        body = json.dumps(response).encode()
                        return self.reply(200, body[:-1] + b',"KeyId":"other"}')
                else:
                    response = {
                        "data": (
                            {
                                "ciphertext": f"vault:v{version}:" + encode(result),
                                "key_version": version,
                            }
                            if encrypt
                            else {"plaintext": encode(result)}
                        ),
                        "warnings": None,
                        "errors": [],
                    }
                    if mutation == "version":
                        response["data"]["key_version"] = 3
                    if mutation == "cipher-version":
                        response["data"]["ciphertext"] = "vault:v3:" + encode(result)
                    if mutation == "duplicate":
                        return self.reply(200, b'{"data":{},"data":{}}')
                value = "CiphertextBlob" if encrypt else "Plaintext"
                data = response if kind == "aws" else response["data"]
                if kind != "aws":
                    value = "ciphertext" if encrypt else "plaintext"
                if mutation == "missing":
                    del data[value]
                if mutation == "base64":
                    data[value] = "not-base64!"
                if mutation == "short-key" and not encrypt:
                    data[value] = encode(b"short")
                if mutation == "errors":
                    response["errors"] = ["fixture error"]
                return self.reply(200, response)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            except Exception as error:
                problems.append(type(error).__name__)
                self.reply(400, {"errors": ["invalid fixture request"]})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 2
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server.server_port, calls, problems
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("fixture service did not stop")
