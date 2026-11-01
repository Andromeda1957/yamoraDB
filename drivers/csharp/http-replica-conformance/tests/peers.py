"""Synthetic, owned TLS peers: adapter controls only, never native qualification."""

import json
import socket
import ssl
import struct
import subprocess
import threading

CLUSTER = "01020304000000000000000000000000"
REVISION = "0123456789abcdef"
SOURCE = b"# receipt\r\nn: 0 # keep\r\n"


def source_tag(source):
    # Specified native source tag; synthetic GET metadata must be consistent.
    value = 1469598103934665603
    for byte in source:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f'"{value:016x}"'


def certificates(root):
    def openssl(*args):
        subprocess.run(
            ["openssl", *args],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=10,
        )

    openssl(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "1",
        "-subj",
        "/CN=adapter synthetic CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
    )
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
            "-subj",
            "/CN=adapter synthetic " + name,
        )
        (root / (name + ".ext")).write_text(
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage="
            + usage
            + "\nsubjectAltName=IP:127.0.0.1\n"
        )
        openssl(
            "x509",
            "-req",
            "-in",
            name + ".csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "2" if name == "server" else "3",
            "-out",
            name + ".pem",
            "-days",
            "1",
            "-extfile",
            name + ".ext",
        )


class Peer:
    def __init__(self, root, node):
        self.node = node
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(root / "server.pem", root / "server.key")
        self.context.load_verify_locations(root / "ca.pem")
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.set_alpn_protocols(["http/1.1"])
        self.records = []
        self.errors = []
        self.bad_receipt = False
        self.status = None
        self.body_override = None
        self.reject_tls = False
        self.reset_write = False
        self.tls_rejections = 0
        self.write_resets = 0
        self.attempted_writes = []
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        if self.port == 8000:
            self.listener.close()
            raise RuntimeError("owner port allocated")
        self.listener.listen(16)
        self.listener.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def seed(self):
        return {"host": "127.0.0.1", "port": self.port, "node": self.node}

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            try:
                with connection:
                    connection.settimeout(3)
                    if self.reject_tls:
                        # Deliberately fail verified TLS after observing the
                        # real SDK ClientHello; this is a negative peer control.
                        hello = connection.recv(4096)
                        if hello.startswith(b"\x16\x03"):
                            self.tls_rejections += 1
                        connection.sendall(b"HTTP/1.1 400 Synthetic TLS rejection\r\n\r\n")
                        continue
                    with self.context.wrap_socket(connection, server_side=True) as stream:
                        self.exchange(stream)
            except (ssl.SSLError, OSError):
                pass
            except Exception as error:
                self.errors.append(error)

    def exchange(self, stream):
        raw = b""
        while b"\r\n\r\n" not in raw:
            part = stream.recv(4096)
            if not part:
                return
            raw += part
            if len(raw) > 16384:
                raise RuntimeError("unbounded HTTP headers")
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.decode("ascii").split("\r\n")
        method, path, _ = lines[0].split()
        headers = {
            key.lower(): value.strip() for key, value in (line.split(":", 1) for line in lines[1:])
        }
        length = int(headers.get("content-length", "0"))
        if length > 131072:
            raise RuntimeError("unbounded body")
        if self.reset_write and method in ("PUT", "PATCH", "DELETE"):
            self.attempted_writes.append((method, path, headers))
            self.write_resets += 1
            # Close while the SDK may still be writing the bounded source.
            # SO_LINGER(0) produces a real TCP reset, not a fabricated API error.
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        while len(body) < length:
            part = stream.recv(min(4096, length - len(body)))
            if not part:
                raise RuntimeError("truncated body")
            body += part
        self.records.append((method, path, headers, body))
        status, media, extra = 200, "application/json", []
        if path == "/v1/cluster/status":
            value = {
                "node": self.node,
                "leader": self.node,
                "term": 1,
                "role": "leader",
                "voters": 3,
                "last": 1,
                "committed": 1,
                "applied": 1,
                "failed": False,
            }
        elif path == "/v1/changes":
            token = "v1." + CLUSTER + ".0000000000000001"
            value = {
                "checkpoint": token,
                "next_after": token,
                "oldest_after": token,
                "transactions": [],
                "has_more": False,
            }
        elif method == "GET":
            value = None
            body = self.body_override if self.body_override is not None else SOURCE
            media = "application/yaml"
            extra = [("ETag", source_tag(body))]
        elif self.status is not None:
            status, value = self.status, {"error": "SYNTHETIC-PEER-SECRET"}
        elif self.bad_receipt:
            value = {"status": "SYNTHETIC-PEER-SECRET"}
        elif method == "DELETE":
            status, value, body = 204, None, b""
        else:
            parts = path.split("/")
            value = {
                "status": "stored",
                "collection": parts[3],
                "document": parts[5],
                "etag": REVISION,
                "revision": REVISION,
            }
            status = 201 if "if-none-match" in headers else 200
            extra = [("ETag", '"' + REVISION + '"')]
        if value is not None:
            body = json.dumps(value, separators=(",", ":")).encode()
        fields = [
            ("Content-Type", media),
            ("X-YamlDB-Revision", REVISION),
            ("Connection", "close"),
            ("Content-Length", str(len(body))),
            *extra,
        ]
        response = (
            f"HTTP/1.1 {status} Test\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fields) + "\r\n"
        ).encode() + body
        stream.sendall(response)

    def close(self):
        self.stopped.set()
        self.thread.join(5)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError("owned peer did not stop")
        if self.errors:
            raise self.errors[0]
