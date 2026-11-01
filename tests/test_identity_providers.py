"""Native adapters against isolated TLS/LDAPS services and system Kerberos.

No external provider, account, network credential or KDC is used. The local STS
fixture independently checks SigV4. Kerberos tickets use system MIT crypto.
"""

import base64
import copy
import ctypes as C
import hashlib
import hmac
import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

NOW = 1800000000
SIGNED = "host;x-amz-date;x-amz-security-token;x-yamora-server-id"
ACCESS = "ASIALOCALFIXTURE00001"
SECRET = "synthetic-local-signing-key"
SESSION = "synthetic-session-token"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def aws_signature(host, date, server, body):
    scope = date[:8] + "/us-east-1/sts/aws4_request"
    headers = f"host:{host}\nx-amz-date:{date}\nx-amz-security-token:{SESSION}\nx-yamora-server-id:{server}\n"
    canonical = f"POST\n/\n\n{headers}\n{SIGNED}\n{hashlib.sha256(body).hexdigest()}"
    message = f"AWS4-HMAC-SHA256\n{date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    key = ("AWS4" + SECRET).encode()
    for word in (date[:8], "us-east-1", "sts", "aws4_request"):
        key = hmac.digest(key, word.encode(), "sha256")
    signature = hmac.digest(key, message.encode(), "sha256").hex()
    return f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, SignedHeaders={SIGNED}, Signature={signature}"


class HTTPFixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append((self.path, self.command, dict(self.headers), body))
        try:
            status, payload, content_type = self.server.routes[self.path](self, body)
        except (ssl.SSLError, ConnectionError):
            return
        if not status:
            return
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        if payload:
            self.send_header("Content-Type", content_type)
        try:
            self.end_headers()
            self.wfile.write(payload)
        except (ssl.SSLError, ConnectionError):
            pass

    do_GET = handle_request
    do_POST = handle_request


def ber(tag, data):
    if len(data) < 128:
        length = bytes([len(data)])
    elif len(data) < 256:
        length = b"\x81" + bytes([len(data)])
    else:
        length = b"\x82" + len(data).to_bytes(2, "big")
    return bytes([tag]) + length + data


class LDAPFixture(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request, server_side=True) as stream:
                received = stream.recv(4096)
                self.server.requests.append(received)
                expected = ber(
                    0x30,
                    b"\x02\x01\x01"
                    + ber(
                        0x60,
                        b"\x02\x01\x03"
                        + ber(4, self.server.dn.encode())
                        + ber(0x80, self.server.password.encode()),
                    ),
                )
                code = 0 if received == expected else 49
                reply = ber(0x30, b"\x02\x01\x01" + ber(0x61, bytes([10, 1, code, 4, 0, 4, 0])))
                stream.sendall(self.server.override if self.server.override is not None else reply)
        except (ssl.SSLError, ConnectionError):
            pass


# System MIT public ABI structures used only to manufacture isolated test tickets.
# The crypto, ticket encoding, ccache, keytab and GSS exchange run in libkrb5/GSS.
class KData(C.Structure):
    _fields_ = [("magic", C.c_int32), ("length", C.c_uint), ("data", C.c_void_p)]


class KKey(C.Structure):
    _fields_ = [
        ("magic", C.c_int32),
        ("enctype", C.c_int32),
        ("length", C.c_uint),
        ("contents", C.c_void_p),
    ]


class KTimes(C.Structure):
    _fields_ = [(name, C.c_int32) for name in ("auth", "start", "end", "renew")]


class KTransited(C.Structure):
    _fields_ = [("magic", C.c_int32), ("type", C.c_ubyte), ("contents", KData)]


class KPart(C.Structure):
    _fields_ = [
        ("magic", C.c_int32),
        ("flags", C.c_int32),
        ("session", C.POINTER(KKey)),
        ("client", C.c_void_p),
        ("transited", KTransited),
        ("times", KTimes),
        ("addresses", C.c_void_p),
        ("authdata", C.c_void_p),
    ]


class KEncrypted(C.Structure):
    _fields_ = [
        ("magic", C.c_int32),
        ("enctype", C.c_int32),
        ("kvno", C.c_uint),
        ("ciphertext", KData),
    ]


class KTicket(C.Structure):
    _fields_ = [
        ("magic", C.c_int32),
        ("server", C.c_void_p),
        ("encrypted", KEncrypted),
        ("part", C.POINTER(KPart)),
    ]


class KCred(C.Structure):
    _fields_ = [
        ("magic", C.c_int32),
        ("client", C.c_void_p),
        ("server", C.c_void_p),
        ("key", KKey),
        ("times", KTimes),
        ("skey", C.c_uint),
        ("flags", C.c_int32),
        ("addresses", C.c_void_p),
        ("ticket", KData),
        ("second", KData),
        ("authdata", C.c_void_p),
    ]


class KEntry(C.Structure):
    _fields_ = [
        ("magic", C.c_int32),
        ("principal", C.c_void_p),
        ("timestamp", C.c_int32),
        ("kvno", C.c_uint),
        ("key", KKey),
    ]


class GBuffer(C.Structure):
    _fields_ = [("length", C.c_size_t), ("value", C.c_void_p)]


class GOID(C.Structure):
    _fields_ = [("length", C.c_uint32), ("value", C.c_void_p)]


class GBindings(C.Structure):
    _fields_ = [
        ("initiator_type", C.c_uint32),
        ("initiator", GBuffer),
        ("acceptor_type", C.c_uint32),
        ("acceptor", GBuffer),
        ("application", GBuffer),
    ]


class GElement(C.Structure):
    _fields_ = [("key", C.c_char_p), ("value", C.c_char_p)]


class GStore(C.Structure):
    _fields_ = [("count", C.c_uint32), ("elements", C.POINTER(GElement))]


class KerberosFixture:
    """Issue a service ticket offline with fresh AES keys; never contact a KDC."""

    def __init__(self, directory, service="yamora/identity.local@LOCAL.TEST"):
        self.contexts = {}
        self.service = service.encode()
        self.krb = C.CDLL("libkrb5.so.3")
        self.gss = C.CDLL("libgssapi_krb5.so.2")
        self.context = C.c_void_p()
        self.check(self.krb.krb5_init_context(C.byref(self.context)))
        self.client, self.server = C.c_void_p(), C.c_void_p()
        self.check(
            self.krb.krb5_parse_name(self.context, b"alice@LOCAL.TEST", C.byref(self.client))
        )
        self.check(self.krb.krb5_parse_name(self.context, self.service, C.byref(self.server)))
        self.key, self.session = KKey(), KKey()
        self.check(self.krb.krb5_c_make_random_key(self.context, 18, C.byref(self.key)))
        self.check(self.krb.krb5_c_make_random_key(self.context, 18, C.byref(self.session)))
        self.keytab = directory / "identity.keytab"
        kt = C.c_void_p()
        self.check(
            self.krb.krb5_kt_resolve(
                self.context, ("FILE:" + str(self.keytab)).encode(), C.byref(kt)
            )
        )
        now = int(time.time())
        entry = KEntry(0, self.server, now, 1, self.key)
        self.check(self.krb.krb5_kt_add_entry(self.context, kt, C.byref(entry)))
        self.check(self.krb.krb5_kt_close(self.context, kt))
        self.times = KTimes(now - 1, now - 1, now + 600, 0)
        part = KPart(
            0,
            0x00400000,
            C.pointer(self.session),
            self.client,
            KTransited(0, 1, KData()),
            self.times,
            None,
            None,
        )
        ticket = KTicket(0, self.server, KEncrypted(0, 18, 1, KData()), C.pointer(part))
        self.check(self.krb.krb5_encrypt_tkt_part(self.context, C.byref(self.key), C.byref(ticket)))
        data = C.POINTER(KData)()
        self.check(self.krb.encode_krb5_ticket(C.byref(ticket), C.byref(data)))
        self.ccache = directory / "identity.ccache"
        cc = C.c_void_p()
        self.check(
            self.krb.krb5_cc_resolve(
                self.context, ("FILE:" + str(self.ccache)).encode(), C.byref(cc)
            )
        )
        self.check(self.krb.krb5_cc_initialize(self.context, cc, self.client))
        creds = KCred(
            0,
            self.client,
            self.server,
            self.session,
            self.times,
            0,
            part.flags,
            None,
            data.contents,
            KData(),
            None,
        )
        self.check(self.krb.krb5_cc_store_cred(self.context, cc, C.byref(creds)))
        self.check(self.krb.krb5_cc_close(self.context, cc))
        self.krb.krb5_free_data(self.context, data)
        self.krb.krb5_free_data_contents(self.context, C.byref(ticket.encrypted.ciphertext))
        self.binding = bytes(range(32))

    @staticmethod
    def check(code):
        if code:
            raise RuntimeError(f"system Kerberos fixture failed: {code}")

    def token(self, binding=None, spnego=False):
        minor = C.c_uint32()
        name, credential, context = C.c_void_p(), C.c_void_p(), C.c_void_p()
        name_string = C.create_string_buffer(self.service)
        name_buffer = GBuffer(len(name_string.value), C.cast(name_string, C.c_void_p))
        oid_storage = C.create_string_buffer(bytes.fromhex("2a864886f71201020201"))
        name_type = GOID(10, C.cast(oid_storage, C.c_void_p))
        self.check(
            self.gss.gss_import_name(
                C.byref(minor), C.byref(name_buffer), C.byref(name_type), C.byref(name)
            )
        )
        element = GElement(b"ccache", ("FILE:" + str(self.ccache)).encode())
        store = GStore(1, C.pointer(element))
        self.check(
            self.gss.gss_acquire_cred_from(
                C.byref(minor), None, 0, None, 1, C.byref(store), C.byref(credential), None, None
            )
        )
        mechanism_bytes = bytes.fromhex("2b0601050502" if spnego else "2a864886f712010202")
        mechanism_storage = C.create_string_buffer(mechanism_bytes)
        mechanism = GOID(len(mechanism_bytes), C.cast(mechanism_storage, C.c_void_p))
        channel = C.create_string_buffer(self.binding if binding is None else binding)
        bindings = GBindings(
            0, GBuffer(), 0, GBuffer(), GBuffer(len(channel.raw) - 1, C.cast(channel, C.c_void_p))
        )
        output = GBuffer()
        major = self.gss.gss_init_sec_context(
            C.byref(minor),
            credential,
            C.byref(context),
            name,
            C.byref(mechanism),
            2 | 4 | 32,
            0,
            C.byref(bindings),
            None,
            None,
            C.byref(output),
            None,
            None,
        )
        if major != 1:
            raise RuntimeError(f"GSS initiator expected CONTINUE, got {major}/{minor.value}")
        token = C.string_at(output.value, output.length)
        self.gss.gss_release_buffer(C.byref(minor), C.byref(output))
        self.contexts[token] = (context, credential, name, mechanism_storage, channel)
        return token

    def finish(self, token, reply):
        context, credential, name, mechanism_storage, channel = self.contexts.pop(token)
        minor = C.c_uint32()
        mechanism = GOID(9, C.cast(mechanism_storage, C.c_void_p))
        bindings = GBindings(
            0, GBuffer(), 0, GBuffer(), GBuffer(len(channel.raw) - 1, C.cast(channel, C.c_void_p))
        )
        storage = C.create_string_buffer(reply)
        input_buffer = GBuffer(len(reply), C.cast(storage, C.c_void_p))
        output = GBuffer()
        try:
            self.check(
                self.gss.gss_init_sec_context(
                    C.byref(minor),
                    credential,
                    C.byref(context),
                    name,
                    C.byref(mechanism),
                    2 | 4 | 32,
                    0,
                    C.byref(bindings),
                    C.byref(input_buffer),
                    None,
                    C.byref(output),
                    None,
                    None,
                )
            )
        finally:
            self.gss.gss_release_buffer(C.byref(minor), C.byref(output))
            self.gss.gss_delete_sec_context(C.byref(minor), C.byref(context), None)
            self.gss.gss_release_cred(C.byref(minor), C.byref(credential))
            self.gss.gss_release_name(C.byref(minor), C.byref(name))

    def close(self):
        minor = C.c_uint32()
        for context, credential, name, _mechanism, _channel in self.contexts.values():
            self.gss.gss_delete_sec_context(C.byref(minor), C.byref(context), None)
            self.gss.gss_release_cred(C.byref(minor), C.byref(credential))
            self.gss.gss_release_name(C.byref(minor), C.byref(name))
        self.krb.krb5_free_keyblock_contents(self.context, C.byref(self.session))
        self.krb.krb5_free_keyblock_contents(self.context, C.byref(self.key))
        self.krb.krb5_free_principal(self.context, self.client)
        self.krb.krb5_free_principal(self.context, self.server)
        self.krb.krb5_free_context(self.context)


class IdentityProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError("owned managed TMPDIR required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        environment = {name: os.environ.get(name) for name in ("KRB5_CONFIG", "KRB5RCACHEDIR")}
        cls.addClassCleanup(cls.restore_environment, environment)
        config = cls.root / "krb5.conf"
        config.write_text(
            "[libdefaults]\n default_realm = LOCAL.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n[realms]\n LOCAL.TEST = {\n kdc = 127.0.0.1:1\n }\n"
        )
        os.environ["KRB5_CONFIG"] = str(config)
        os.environ["KRB5RCACHEDIR"] = str(cls.root)
        cls.source = Path(__file__).resolve().parents[1]
        cls.binary = cls.build(cls.root / "identity")
        cls.key, cls.cert = cls.root / "tls.key", cls.root / "tls.crt"
        cls.command(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=identity.local",
                "-addext",
                "subjectAltName=DNS:identity.local",
                "-keyout",
                str(cls.key),
                "-out",
                str(cls.cert),
            ]
        )
        cls.jwk = {"kty": "RSA", "alg": "RS256", "kid": "local", "e": "AQAB"}
        modulus = (
            cls.command(["openssl", "rsa", "-in", str(cls.key), "-noout", "-modulus"])
            .split(b"=")[1]
            .strip()
        )
        cls.jwk["n"] = b64(bytes.fromhex(modulus.decode()))
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.minimum_version = ssl.TLSVersion.TLSv1_3
        cls.context.load_cert_chain(cls.cert, cls.key)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTPFixture)
        cls.server.socket = cls.context.wrap_socket(cls.server.socket, server_side=True)
        cls.server.routes, cls.server.requests = {}, []
        cls.origin = f"https://identity.local:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server, cls.server, cls.thread)
        cls.ldap = socketserver.ThreadingTCPServer(("127.0.0.1", 0), LDAPFixture)
        cls.ldap.context, cls.ldap.requests, cls.ldap.override = cls.context, [], None
        cls.ldap_origin = f"ldaps://identity.local:{cls.ldap.server_address[1]}"
        cls.ldap_thread = threading.Thread(target=cls.ldap.serve_forever, daemon=True)
        cls.ldap_thread.start()
        cls.addClassCleanup(cls.stop_server, cls.ldap, cls.ldap_thread)
        cls.kerberos = KerberosFixture(cls.root)
        cls.addClassCleanup(cls.kerberos.close)

    @staticmethod
    def command(command, **kwargs):
        result = subprocess.run(command, capture_output=True, timeout=90, **kwargs)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return result.stdout

    @classmethod
    def build(cls, output, identity_source=None, oidc_source=None):
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-g",
            "-O1",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-pthread",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            str(cls.source / "tests/identity_harness.c"),
            str(identity_source or cls.source / "src/security/identity.c"),
            str(oidc_source or cls.source / "src/security/oidc.c"),
            str(cls.source / "src/security/oidc_json.c"),
            "-I",
            str(cls.source / "src/security"),
            "-lssl",
            "-lcrypto",
            "-ldl",
            "-Wl,--wrap=dlopen",
            "-Wl,--wrap=socket",
            "-Wl,--wrap=send",
            "-Wl,--wrap=poll",
            "-Wl,--wrap=clock_gettime",
            "-Wl,--wrap=SSL_read_ex",
            "-Wl,--wrap=SSL_write_ex",
            "-Wl,--wrap=pthread_setcancelstate",
            "-o",
            str(output),
        ]
        cls.command(command)
        return output

    @staticmethod
    def stop_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("fixture did not stop")

    @staticmethod
    def restore_environment(environment):
        for name, value in environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def setUp(self):
        self.server.routes.clear()
        self.server.requests.clear()
        self.ldap.override = None
        self.ldap.requests.clear()
        self.ldap.dn = "uid=alice,dc=example"
        self.ldap.password = "local-password"

    def call(self, op, binary=None, **kwargs):
        config = {
            "op": op,
            "origin": self.origin,
            "address": "127.0.0.1",
            "ca": str(self.cert),
            "timeout": 1000,
            "now": NOW,
            **kwargs,
        }
        output = (
            self.command([str(binary or self.binary)], input=encoded(config)).decode().splitlines()
        )
        return int(output[0]), output[1:]

    def route(self, path, value, status=200, raw=False, kind="application/json"):
        payload = value if raw else encoded(value)
        self.server.routes[path] = lambda _handler, _body: (status, payload, kind)

    def claims(self):
        return {
            "active": True,
            "iss": self.origin,
            "aud": "yamora",
            "sub": "alice",
            "client_id": "client",
            "token_type": "Bearer",
            "iat": NOW - 10,
            "exp": NOW + 100,
            "scope": "read write",
        }

    def introspect(self, binary=None, **kwargs):
        return self.call(
            "introspect",
            binary=binary,
            url=self.origin + "/introspect",
            id="reader",
            secret="local:secret",
            token="local/token+value",
            issuer=self.origin,
            audience="yamora",
            scope="read",
            **kwargs,
        )

    def test_discovery_pins_issuer_and_every_endpoint(self):
        self.route(
            "/.well-known/openid-configuration",
            {
                "issuer": self.origin,
                "jwks_uri": self.origin + "/keys",
                "introspection_endpoint": self.origin + "/introspect",
                "revocation_endpoint": self.origin + "/revoke",
            },
        )
        result, fields = self.call("discover", issuer=self.origin)
        self.assertEqual(result, 1)
        self.assertEqual(fields[:2], [self.origin, self.origin + "/keys"])
        for bad in (
            {"issuer": self.origin + "/other", "jwks_uri": self.origin + "/keys"},
            {"issuer": self.origin, "jwks_uri": "https://elsewhere.invalid/keys"},
            {"issuer": self.origin, "jwks_uri": "http://identity.local/keys"},
            {
                "issuer": self.origin,
                "jwks_uri": self.origin + "/keys",
                "introspection_endpoint": "https://169.254.169.254/",
            },
        ):
            with self.subTest(bad=bad):
                self.route("/.well-known/openid-configuration", bad)
                result, fields = self.call("discover", issuer=self.origin)
                self.assertEqual(result, -1)
                self.assertTrue(all(not field for field in fields))
        self.route("/keys", {"keys": [self.jwk]})
        result, fields = self.call("jwks", url=self.origin + "/keys")
        self.assertEqual(result, 1)
        discovered_keys = json.loads(fields[1])
        claims = {
            "iss": self.origin,
            "aud": "local-client",
            "sub": "alice",
            "iat": NOW - 1,
            "exp": NOW + 60,
            "nonce": "discovery-nonce",
        }
        self.assertEqual(
            self.call(
                "google",
                issuer=self.origin,
                audience="local-client",
                jwks=json.dumps(discovered_keys),
                token=self.token(claims),
                nonce="discovery-nonce",
            )[0],
            1,
        )

    def test_introspection_authentication_revocation_and_claims(self):
        expected = b"Basic " + base64.b64encode(b"reader:local%3Asecret")
        revoked = False

        def provider(handler, body):
            if handler.headers["Authorization"].encode() != expected:
                return 401, b"", "application/json"
            form = urllib.parse.parse_qs(body.decode())
            if form != {"token": ["local/token+value"], "token_type_hint": ["access_token"]}:
                return 400, b"", "application/json"
            return 200, encoded({"active": False} if revoked else self.claims()), "application/json"

        def revoke(handler, body):
            nonlocal revoked
            if handler.headers["Authorization"].encode() != expected:
                return 401, b"", "application/json"
            if urllib.parse.parse_qs(body.decode()).get("token") != ["local/token+value"]:
                return 400, b"", "application/json"
            revoked = True
            return 200, b"", "application/json"

        self.server.routes["/introspect"] = provider
        self.assertEqual(self.introspect(), (1, ["alice", "client", str(NOW + 100), "1"]))
        self.server.routes["/revoke"] = revoke
        self.assertEqual(
            self.call(
                "revoke",
                url=self.origin + "/revoke",
                id="reader",
                secret="local:secret",
                token="local/token+value",
            )[0],
            1,
        )
        self.assertEqual(self.introspect()[0], 0)
        revoked = False
        for key, value in (
            ("active", False),
            ("active", "true"),
            ("iss", "other"),
            ("aud", "other"),
            ("scope", "write"),
            ("exp", NOW),
            ("iat", NOW + 1),
            ("token_type", "MAC"),
            ("nbf", NOW + 1),
            ("sub", ""),
        ):
            bad = self.claims()
            bad[key] = value
            self.route("/introspect", bad)
            result, fields = self.introspect()
            self.assertLessEqual(result, 0, (key, value))
            self.assertEqual(fields, ["", "", "0", "0"])
        self.route("/introspect", {"active": False})
        self.assertEqual(self.introspect()[0], 0)
        self.route("/revoke", b"", raw=True)
        self.assertEqual(
            self.call(
                "revoke",
                url=self.origin + "/revoke",
                id="reader",
                secret="secret",
                token="synthetic",
            )[0],
            1,
        )
        self.route("/revoke", b"", status=401, raw=True)
        self.assertEqual(
            self.call(
                "revoke",
                url=self.origin + "/revoke",
                id="reader",
                secret="secret",
                token="synthetic",
            )[0],
            0,
        )

    def test_network_tls_framing_and_limits(self):
        self.route("/keys", {"keys": [self.jwk]})
        self.assertEqual(self.call("jwks", url=self.origin + "/keys")[0], 1)
        for change in (
            {
                "origin": self.origin.replace("identity.local", "wrong.local"),
                "url": self.origin.replace("identity.local", "wrong.local") + "/keys",
            },
            {"ca": str(self.key)},
            {"address": "identity.local"},
            {"url": "https://169.254.169.254/metadata"},
            {"url": self.origin + "@evil/keys"},
        ):
            with self.subTest(change=change):
                self.assertEqual(
                    self.call("jwks", **{"url": self.origin + "/keys", **change})[0], -1
                )
        self.route("/keys", b"x" * 65537, raw=True)
        self.assertEqual(self.call("jwks", url=self.origin + "/keys")[0], -1)
        self.route("/keys", b"", status=302, raw=True)
        self.assertEqual(self.call("jwks", url=self.origin + "/keys")[0], -1)
        self.route("/introspect", b'{"active":true,"active":false}', raw=True)
        self.assertEqual(self.introspect()[0], -1)

        def slow(_handler, _body):
            time.sleep(0.15)
            return 200, b"{}", "application/json"

        self.server.routes["/keys"] = slow
        self.assertEqual(self.call("jwks", url=self.origin + "/keys", timeout=30)[0], -1)

    def test_ldap_bind_checks_password_protocol_and_tls(self):
        def call(**kwargs):
            return self.call(
                "ldap",
                **{
                    "origin": self.ldap_origin,
                    "dn": "uid=alice,dc=example",
                    "password": "local-password",
                    **kwargs,
                },
            )[0]

        self.assertEqual(call(), 1)
        self.assertEqual(call(password="wrong"), 0)
        before = len(self.ldap.requests)
        self.assertEqual(call(password=""), -1)
        self.assertEqual(call(dn=""), -1)
        self.assertEqual(len(self.ldap.requests), before)
        for reply in (
            b"\x30\x80\x00\x00",
            b"\x30\x0c\x02\x01\x02\x61\x07\x0a\x01\x00\x04\x00\x04\x00",
            b"\x30\x0e\x02\x01\x01\x61\x09\x0a\x01\x00\x04\x00\x04\x00\xa3\x00",
        ):
            self.ldap.override = reply
            self.assertEqual(call(), -1)
        self.ldap.override = None
        self.assertEqual(call(ca=str(self.key)), -1)
        self.ldap.dn, self.ldap.password = "uid=álîce,dc=example", "pässwörd"
        self.assertEqual(call(dn=self.ldap.dn, password=self.ldap.password), 1)

    def test_aws_sigv4_fixed_request_audience_and_sts_denial(self):
        date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(NOW))
        server_id = "yamora-local-audience"
        authorization = aws_signature(
            self.origin.split("//")[1],
            date,
            server_id,
            b"Action=GetCallerIdentity&Version=2011-06-15",
        )
        arn = "arn:aws:sts::123456789012:assumed-role/Local/session"

        def sts(handler, body):
            expected = aws_signature(
                handler.headers["Host"],
                handler.headers["X-Amz-Date"],
                handler.headers["X-Yamora-Server-ID"],
                body,
            )
            if not hmac.compare_digest(handler.headers["Authorization"], expected):
                return 403, b"", "text/xml"
            return (
                200,
                f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>{arn}</Arn><Account>123456789012</Account><UserId>LOCAL:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>'.encode(),
                "text/xml",
            )

        self.server.routes["/"] = sts

        def call(**kwargs):
            return self.call(
                "aws",
                **{
                    "url": self.origin + "/",
                    "server_id": server_id,
                    "authorization": authorization,
                    "date": date,
                    "session_token": SESSION,
                    **kwargs,
                },
            )

        self.assertEqual(call(), (1, [arn, "123456789012"]))
        self.assertEqual(call(server_id="other-audience"), (0, ["", ""]))
        self.assertEqual(
            call(authorization=authorization[:-1] + ("0" if authorization[-1] != "0" else "1"))[0],
            0,
        )
        self.assertEqual(call(now=NOW + 61)[0], 0)
        self.assertEqual(call(authorization=authorization.replace(";x-yamora-server-id", ""))[0], 0)
        valid = f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>{arn}</Arn><Account>123456789012</Account><UserId>LOCAL:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>'
        for malformed in (
            valid + "trailing",
            valid.replace("</Arn>", "</Arn><Arn>duplicate</Arn>"),
            valid.replace("<Account>123456789012", "<Account>000000000000"),
            valid.replace("<UserId>", "<Unknown>"),
            valid.replace("</GetCallerIdentityResult>", ""),
        ):
            self.route("/", malformed.encode(), raw=True, kind="text/xml")
            self.assertEqual(call(), (-1, ["", ""]))
        self.route(
            "/",
            b"<!DOCTYPE x><GetCallerIdentityResponse><Arn>x</Arn><Account>123456789012</Account></GetCallerIdentityResponse>",
            raw=True,
            kind="text/xml",
        )
        self.assertEqual(call()[0], -1)

    def token(self, claims, header=None):
        first = b64(encoded(header or {"alg": "RS256", "typ": "JWT", "kid": "local"}))
        message = (first + "." + b64(encoded(claims))).encode()
        signature = self.command(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key)], input=message
        )
        return message.decode() + "." + b64(signature)

    def test_google_shaped_id_token_is_separate_and_nonce_bound(self):
        claims = {
            "iss": "https://accounts.google.com",
            "aud": "client.apps.googleusercontent.com",
            "azp": "client.apps.googleusercontent.com",
            "sub": "10987654321",
            "iat": NOW - 10,
            "exp": NOW + 100,
            "nonce": "local-nonce",
            "email_verified": True,
        }

        def call(**kwargs):
            return self.call(
                "google",
                **{
                    "issuer": claims["iss"],
                    "audience": claims["aud"],
                    "jwks": json.dumps({"keys": [self.jwk]}),
                    "token": self.token(claims),
                    "nonce": "local-nonce",
                    **kwargs,
                },
            )

        self.assertEqual(call(), (1, [claims["sub"], claims["aud"]]))
        self.assertEqual(call(as_access=1)[0], -1)
        self.assertEqual(call(nonce="other")[0], 0)
        for key, value in (
            ("iss", "https://other.invalid"),
            ("aud", "other"),
            ("azp", "other"),
            ("exp", NOW),
        ):
            bad = copy.deepcopy(claims)
            bad[key] = value
            self.assertEqual(call(token=self.token(bad))[0], 0)
        self.assertEqual(
            call(token=self.token(claims, {"alg": "RS256", "typ": "at+jwt", "kid": "local"}))[0], 0
        )

    def test_kerberos_real_ticket_binding_replay_and_keytab(self):
        fixture = self.kerberos

        def call(**kwargs):
            return self.call(
                "kerberos",
                **{
                    "principal": "yamora/identity.local@LOCAL.TEST",
                    "keytab": str(fixture.keytab),
                    "token": fixture.token().hex(),
                    "binding": fixture.binding.hex(),
                    **kwargs,
                },
            )

        token = fixture.token().hex()
        result, fields = call(token=token)
        self.assertEqual(result, 1)
        self.assertEqual(fields[0], "alice@LOCAL.TEST")
        self.assertGreater(len(bytes.fromhex(fields[1])), 0)
        fixture.finish(bytes.fromhex(token), bytes.fromhex(fields[1]))
        self.assertEqual(call(token=token), (0, ["", ""]))
        self.assertEqual(call(binding=(b"x" * 32).hex()), (0, ["", ""]))
        self.assertEqual(call(principal="other/identity.local@LOCAL.TEST")[0], 0)
        self.assertEqual(call(keytab=str(self.root / "absent.keytab"))[0], -1)
        self.assertEqual(call(no_backend=1)[0], -1)
        self.assertEqual(call(token="00010203"), (0, ["", ""]))
        self.assertEqual(call(token=fixture.token(spnego=True).hex()), (0, ["", ""]))

    def test_clock_failure_and_pending_cancellation_cleanup(self):
        def single_record(handler, _body):
            handler.connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}"
            )
            return 0, b"", "application/json"

        self.server.routes["/clock"] = single_record
        self.assertEqual(self.call("jwks", url=self.origin + "/clock")[0], 1)
        self.assertEqual(
            self.call("jwks", url=self.origin + "/clock", fail_clock_after_read=1)[0], -1
        )
        self.assertEqual(
            self.call("jwks", url=self.origin + "/clock", fail_clock_after_write=1)[0], -1
        )

        def withheld(_handler, _body):
            time.sleep(0.3)
            return 200, b"{}", "application/json"

        self.server.routes["/withheld"] = withheld
        self.assertEqual(
            self.call("cancel", issuer=self.origin, url=self.origin + "/withheld", timeout=100)[0],
            1,
        )

        def reset(handler, _body):
            handler.connection.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            handler.connection.close()
            return 0, b"", "application/json"

        self.server.routes["/reset"] = reset
        self.assertEqual(self.call("jwks", url=self.origin + "/reset")[0], -1)

    def test_constructor_pending_cancellation_frees_owner(self):
        self.assertEqual(
            self.call(
                "cancel_constructor",
                principal="yamora/identity.local@LOCAL.TEST",
                keytab=str(self.kerberos.keytab),
            )[0],
            1,
        )

    def test_socket_and_cancellation_guard_controls(self):
        source = (self.source / "src/security/identity.c").read_text()
        self.route("/keys", {})

        def withheld(_handler, _body):
            time.sleep(0.3)
            return 200, b"{}", "application/json"

        self.server.routes["/withheld"] = withheld
        cases = (
            ("cloexec", " | SOCK_CLOEXEC", "", "jwks", "socket flags"),
            ("sigpipe", "data, size, MSG_NOSIGNAL", "data, size, 0", "jwks", "socket flags"),
            (
                "cancel",
                "if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return YD_IDENTITY_ERROR;",
                "prior = PTHREAD_CANCEL_ENABLE; if (false) return YD_IDENTITY_ERROR;",
                "cancel",
                "socket flags",
            ),
            (
                "constructor",
                "static void cancelled_constructor(void *object) { kerberos_free(object); }",
                "static void cancelled_constructor(void *object) { (void)object; }",
                "cancel_constructor",
                "LeakSanitizer",
            ),
        )
        for name, old, new, operation, diagnostic in cases:
            with self.subTest(control=name):
                path = self.root / ("lifecycle-" + name + ".c")
                self.assertEqual(source.count(old), 1)
                path.write_text(source.replace(old, new))
                binary = self.build(self.root / ("lifecycle-" + name), identity_source=path)
                config = {
                    "origin": self.origin,
                    "address": "127.0.0.1",
                    "ca": str(self.cert),
                    "timeout": 100,
                    "now": NOW,
                    "url": self.origin + ("/withheld" if operation == "cancel" else "/keys"),
                    "issuer": self.origin,
                    "principal": "yamora/identity.local@LOCAL.TEST",
                    "keytab": str(self.kerberos.keytab),
                }
                result = subprocess.run(
                    [str(binary)],
                    input=encoded({"op": operation, **config}),
                    capture_output=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr.decode(errors="replace"))
                self.assertEqual(self.call(operation, **config)[0], 1)
                print(
                    f"control {name}: compiled, native lifecycle failure, restored pass", flush=True
                )

    def test_independent_guard_removal_controls(self):
        source = (self.source / "src/security/identity.c").read_text()
        cases = {
            "issuer": ('!eq(get(root, "issuer"), issuer)', "false"),
            "active": ('if (strcmp(active->text, "true")) goto done;', "if (false) goto done;"),
            "tls": ("SSL_set1_host(c->ssl, t->host)", "SSL_set_tlsext_host_name(c->ssl, t->host)"),
            "ldap": (
                "result = code == 0 ? YD_IDENTITY_VALID : YD_IDENTITY_INVALID;",
                "(void)code; result = YD_IDENTITY_VALID;",
            ),
            "gss_binding": (
                "(flags & required) != required",
                "(flags & (required & ~2048U)) != (required & ~2048U)",
            ),
            "aws_time": (
                "if (stamp < now - 60 || stamp > now + 5) return YD_IDENTITY_INVALID;",
                "(void)stamp;",
            ),
            "clock": (
                "return now >= 0 && now < c->deadline;",
                "return now < c->deadline;",
            ),
            "gss_target": (
                "k->compare(&minor, target_name, k->expected_name, &same) != 0 || !same",
                "k->compare(&minor, target_name, k->expected_name, &same) != 0 || (same && false)",
            ),
        }
        # Each control must compile, then fail the same behavioral test method.
        tests = {
            "issuer": "test_discovery_pins_issuer_and_every_endpoint",
            "active": "test_introspection_authentication_revocation_and_claims",
            "tls": "test_network_tls_framing_and_limits",
            "ldap": "test_ldap_bind_checks_password_protocol_and_tls",
            "gss_binding": "test_kerberos_real_ticket_binding_replay_and_keytab",
            "aws_time": "test_aws_sigv4_fixed_request_audience_and_sts_denial",
            "clock": "test_clock_failure_and_pending_cancellation_cleanup",
            "gss_target": "test_kerberos_real_ticket_binding_replay_and_keytab",
        }
        for name, (old, new) in cases.items():
            with self.subTest(control=name):
                self.assertEqual(source.count(old), 1)
                path = self.root / (name + ".c")
                broken = source.replace(old, new)
                if name == "gss_binding":
                    broken = broken.replace("&input, &bindings,", "&input, NULL,")
                    broken = broken.replace(
                        "GBindings bindings = {0};", "GBindings bindings = {0}; (void)bindings;"
                    )
                path.write_text(broken)
                binary = self.build(self.root / (name + "-identity"), identity_source=path)
                probe = type(self)(tests[name])
                probe.binary = binary
                outcome = unittest.TestResult()
                probe.run(outcome)
                self.assertEqual(outcome.errors, [])
                self.assertGreater(
                    len(outcome.failures), 0, "guard removal did not fail its behavioral test"
                )
                restored = unittest.TestResult()
                type(self)(tests[name]).run(restored)
                self.assertTrue(restored.wasSuccessful(), restored.errors + restored.failures)
                print(
                    f"control {name}: compiled, behavioral rejection failed, restored pass",
                    flush=True,
                )

    def test_kerberos_rotated_keytab_rejects_old_and_wrong_keys(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            replacement = KerberosFixture(Path(directory))
            try:
                token = replacement.token()
                options = {
                    "principal": "yamora/identity.local@LOCAL.TEST",
                    "token": token.hex(),
                    "binding": replacement.binding.hex(),
                }
                self.assertEqual(
                    self.call("kerberos", keytab=str(self.kerberos.keytab), **options),
                    (0, ["", ""]),
                )
                result, fields = self.call("kerberos", keytab=str(replacement.keytab), **options)
                self.assertEqual(result, 1)
                replacement.finish(token, bytes.fromhex(fields[1]))
                self.assertEqual(
                    self.call(
                        "kerberos",
                        principal=options["principal"],
                        token=self.kerberos.token().hex(),
                        binding=self.kerberos.binding.hex(),
                        keytab=str(replacement.keytab),
                    ),
                    (0, ["", ""]),
                )
            finally:
                replacement.close()


if __name__ == "__main__":
    unittest.main()
