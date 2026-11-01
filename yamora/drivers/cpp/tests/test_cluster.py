"""Public ClusterClient acceptance over hostile HTTPS and real native mTLS peers."""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import re
import selectors
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import test_driver as wire

PROBE = wire.PROBE
CLUSTER = "c" * 32
REV = wire.REVISION
BINARY = os.environ.get("YAMORA_TEST_BINARY", "")
BINARY_HASH = None


def setUpModule():
    global BINARY_HASH
    if not Path(BINARY).is_absolute() or not os.access(BINARY, os.X_OK):
        raise RuntimeError("existing absolute YAMORA_TEST_BINARY required; no native skips/builds")
    BINARY_HASH = hashlib.sha256(Path(BINARY).read_bytes()).hexdigest()
    wire.setUpModule()
    try:
        for node in range(1, 4):
            name = f"node{node}"
            wire.command(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    f"/CN={name}.test",
                    "-keyout",
                    str(wire.CERTS / f"{name}.key"),
                    "-out",
                    str(wire.CERTS / f"{name}.csr"),
                ]
            )
            ext = wire.CERTS / f"{name}.ext"
            ext.write_text(
                f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,DNS:{name}.test\n"
            )
            wire.command(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(wire.CERTS / f"{name}.csr"),
                    "-CA",
                    str(wire.CERTS / "ca.pem"),
                    "-CAkey",
                    str(wire.CERTS / "ca.key"),
                    "-set_serial",
                    str(10 + node),
                    "-days",
                    "1",
                    "-extfile",
                    str(ext),
                    "-out",
                    str(wire.CERTS / f"{name}.pem"),
                ]
            )
    except BaseException:
        wire.tearDownModule()
        raise


def tearDownModule():
    try:
        if hashlib.sha256(Path(BINARY).read_bytes()).hexdigest() != BINARY_HASH:
            raise AssertionError("immutable native daemon changed")
    finally:
        wire.tearDownModule()


def status(node=1):
    return {
        "node": node,
        "leader": node,
        "role": "leader",
        "term": 1,
        "voters": 3,
        "last": 0,
        "committed": 0,
        "applied": 0,
        "failed": False,
        "checkpoints": {},
        "compaction": {},
        "application_compaction": {"last_result": 0, "future_counter": 9},
    }


def checkpoint():
    token = f"v1.{CLUSTER}.0000000000000000"
    return {
        "checkpoint": token,
        "next_after": token,
        "oldest_after": token,
        "transactions": [],
        "has_more": False,
        "revision": REV,
    }


def reply(value, code=200, extra=b"", revision=REV):
    body = (
        json.dumps(value, separators=(",", ":")).encode() if not isinstance(value, bytes) else value
    )
    return wire.frame(body, status=code, extra=extra).replace(REV.encode(), revision.encode())


def stored(document="one", collection="examples", tag=REV):
    return {
        "status": "stored",
        "collection": collection,
        "document": document,
        "etag": tag,
        "revision": REV,
    }


def stored_reply(code=201, value=None):
    return reply(stored() if value is None else value, code, extra=f'ETag: "{REV}"\r\n'.encode())


class Peer:
    def __init__(self, handle=None, *, node=1, handshake_delay=0):
        self.handle = handle or (lambda req: reply({"revision": REV}))
        self.metadata, self.feed = reply(status(node)), reply(checkpoint())
        self.requests, self.failures = [], []
        self.handshake_delay = handshake_delay
        self.accepted = 0
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        if self.port == 8000:
            raise RuntimeError("owner port")
        self.listener.listen(64)
        self.listener.settimeout(0.05)
        self.workers = []
        self.context = wire.tls_context()
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(wire.CERTS / "ca.pem")
        self.thread = threading.Thread(target=self.serve)

    def serve(self):
        while not self.stop.is_set():
            try:
                sock, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.accepted += 1
            worker = threading.Thread(target=self.exchange, args=(sock,))
            self.workers.append(worker)
            worker.start()

    def exchange(self, sock):
        try:
            with sock:
                sock.settimeout(4)
                if self.stop.wait(self.handshake_delay):
                    return
                with self.context.wrap_socket(sock, server_side=True) as connection:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        part = connection.recv(4096)
                        if not part:
                            return
                        data += part
                    head, body = data.split(b"\r\n\r\n", 1)
                    lines = head.split(b"\r\n")
                    method, path, _ = lines[0].decode().split()
                    headers = dict(line.decode().split(": ", 1) for line in lines[1:])
                    size = int(headers.get("Content-Length", 0))
                    while len(body) < size:
                        part = connection.recv(min(65536, size - len(body)))
                        if not part:
                            return
                        body += part
                    request = method, path, headers, body
                    self.requests.append(request)
                    if path == "/v1/cluster/status":
                        response = self.metadata
                    elif path == "/v1/changes":
                        response = self.feed
                    else:
                        response = self.handle(request)
                    if callable(response):
                        response = response(request)
                    if response is not None:
                        connection.sendall(response)
        except (OSError, ssl.SSLError):
            pass  # deliberate cancellation, drops, and peer rejection
        except BaseException as error:
            self.failures.append(error)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.listener.close()
        self.thread.join(5)
        for worker in self.workers:
            worker.join(5)
            if worker.is_alive():
                raise AssertionError("HTTPS fixture worker leaked")
        if self.failures:
            raise self.failures[0]

    def mutations(self):
        return [
            r
            for r in self.requests
            if r[0] in ("PUT", "PATCH", "DELETE") or r[1] == "/v1/transactions"
        ]


def settings(seeds, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CPP_")}
    env.update(
        CPP_SEEDS=",".join(f"{p}:{n}" for p, n in seeds),
        CPP_CA=str(wire.CERTS / "ca.pem"),
        CPP_CERT=str(wire.CERTS / "client.pem"),
        CPP_KEY=str(wire.CERTS / "client.key"),
    )
    env.update({k: str(v) for k, v in extra.items()})
    return env


class Helpers(unittest.TestCase):
    def invoke(
        self, seeds, mode="health", body=b"", collection="examples", document="one", **extra
    ):
        return subprocess.run(
            [PROBE, mode, collection, document],
            input=body,
            capture_output=True,
            env=settings(seeds, **extra),
            timeout=35,
        )

    def good(self, seeds, mode="health", body=b"", **extra):
        p = self.invoke(seeds, mode, body, **extra)
        self.assertEqual(p.returncode, 0, (p.stdout, p.stderr))
        code, revision, tag, body = p.stdout.split(b"\n", 3)
        return int(code), revision.decode(), tag.decode(), body

    def bad(self, seeds, mode="health", body=b"", *, kind=None, code=None, uncertain=0, **extra):
        p = self.invoke(seeds, mode, body, **extra)
        self.assertEqual(p.returncode, 2, (p.stdout, p.stderr))
        observed = [int(x) for x in p.stderr.splitlines()[0].split()]
        for actual, expected in zip(observed, [kind, code, uncertain], strict=True):
            if expected is not None:
                self.assertEqual(actual, expected, p.stderr)
        self.assertNotIn(wire.READ.encode(), p.stderr)
        self.assertNotIn(wire.WRITE.encode(), p.stderr)
        return p

    @contextlib.contextmanager
    def controlled(self, seeds, mode, **extra):
        p = subprocess.Popen(
            [PROBE, mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=settings(seeds, CPP_CONTROL=1, **extra),
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(p.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(5), "probe did not start")
            self.assertEqual(p.stdout.readline(), b"START\n")
            yield p
        finally:
            if p.poll() is None:
                p.kill()
            p.wait(5)
            for stream in (p.stdin, p.stdout, p.stderr):
                stream.close()


class HostileAcceptance(Helpers):
    def test_unsupported_profile_operations_never_discover_or_dispatch(self):
        with Peer() as peer:
            for mode, body, extra in [
                ("start_index_build", b'{"indexes":[]}', {}),
                ("index_build", b"", {}),
                ("cancel_index_build", b"", {"CPP_JOB_ID": "a" * 32}),
                ("replication_status", b"", {}),
                *[
                    (f"{prefix}_{phase}", b"{}", {})
                    for prefix in ("replication", "follow")
                    for phase in ("begin", "apply", "commit", "abort")
                ],
            ]:
                with self.subTest(mode=mode):
                    self.bad([(peer.port, 1)], mode, body, kind=0, code=0, **extra)
            self.assertEqual(peer.requests, [])

    def test_configuration_validation(self):
        with Peer() as peer:
            for extra in [
                {"CPP_NO_TLS": 1},
                {"CPP_CLUSTER_ID": "0" * 32},
                {"CPP_CLUSTER_ID": "f" * 31},
                {"CPP_VOTERS": 4},
                {"CPP_VOTERS": 1},
                {"CPP_VOTERS": 11},
                {"CPP_TIMEOUT": 0},
                {"CPP_ATTEMPT_TIMEOUT": 30001},
                {"CPP_HOST": "8.8.8.8"},
                {"CPP_SEEDS": f"{peer.port}:1,{peer.port}:2"},
                {"CPP_SEEDS": f"{peer.port}:1,{peer.port + 1}:1"},
                {"CPP_SEEDS": "1:0"},
                {"CPP_SEEDS": ""},
            ]:
                with self.subTest(extra=extra):
                    self.bad([(peer.port, 1)], "config", kind=0, **extra)
            self.assertEqual(peer.requests, [])

    def test_strict_metadata_and_feed_prevent_dispatch(self):
        variants = []
        for field, value in [
            ("node", True),
            ("node", 1.0),
            ("leader", 2),
            ("voters", 5),
            ("term", 0),
            ("term", 2**64),
            ("role", "follower"),
            ("failed", True),
            ("applied", 1),
        ]:
            v = status()
            v[field] = value
            variants.append((reply(v), reply(checkpoint())))
        raw = json.dumps(status()).encode()
        variants += [
            (reply(raw[:-1] + b',"node":1}'), reply(checkpoint())),
            (
                reply(raw.replace(b'"node"', b'"\\u006eode"')[:-1] + b',"node":1}'),
                reply(checkpoint()),
            ),
            (reply(raw[:-1] + b',"x":"\xed\xa0\x80"}'), reply(checkpoint())),
            (reply(raw[:-1] + b',"x":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"), reply(checkpoint())),
        ]
        for field, value in [
            ("checkpoint", f"v1.{'d' * 32}.{'0' * 16}"),
            ("next_after", f"v1.{CLUSTER}.{'1' * 16}"),
            ("has_more", 0),
            ("transactions", {}),
            ("oldest_after", "bad"),
        ]:
            v = checkpoint()
            v[field] = value
            variants.append((reply(status()), reply(v)))
        variants += [
            (
                reply(status(), extra=b"X-YamlDB-Revision: 0000000000000000\r\n"),
                reply(checkpoint()),
            ),
            (
                reply(status(), extra=b"Cache-Control: no-store\r\nCache-Control: public\r\n"),
                reply(checkpoint()),
            ),
            (reply(status(), extra=b"Content-Length: 0\r\n"), reply(checkpoint())),
        ]
        for meta, feed in variants:
            with self.subTest(meta=meta, feed=feed), Peer() as peer:
                peer.metadata, peer.feed = meta, feed
                self.bad([(peer.port, 1)], CPP_TIMEOUT=140, CPP_ATTEMPT_TIMEOUT=70)
                self.assertFalse(any(r[1] == "/healthz" for r in peer.requests))

    def test_no_store_exception_numeric_fidelity_and_slow_connect_survives_polling(self):
        payload = (
            b'{"revision":"'
            + REV.encode()
            + b'","wide":18446744073709551615,"decimal":1.23000e+30,"escaped":"\\u0061"}'
        )
        with Peer(lambda req: reply(payload), handshake_delay=0.06) as peer:
            peer.metadata = reply(
                status(), extra=b"Cache-Control: no-store\r\nCache-Control: no-store\r\n"
            )
            self.assertEqual(self.good([(peer.port, 1)], CPP_TIMEOUT=1800)[3], payload)
            self.assertEqual(peer.accepted, 3, "polling restarted an in-flight handshake")

    def test_fair_discovery_hints_and_redirects_never_choose_destinations(self):
        with Peer() as trap, Peer() as bad, Peer() as healthy:

            def stall(req):
                bad.stop.wait(0.2)
                return reply(status())

            bad.metadata = stall
            self.good([(bad.port, 2), (healthy.port, 1)], CPP_TIMEOUT=700, CPP_ATTEMPT_TIMEOUT=200)
            bad.metadata = reply({**status(), "leader": 2, "host": "127.0.0.1", "port": trap.port})
            healthy.handle = lambda req: reply(
                b"remote detail",
                307,
                extra=f"Location: https://127.0.0.1:{trap.port}/leak\r\n".encode(),
            )
            self.bad([(bad.port, 2), (healthy.port, 1)], code=307)
            self.assertEqual(trap.requests, [])

    def test_hostile_receipts_retain_frozen_generated_id_and_inputs(self):
        variants = [
            stored_reply(value={**stored(), "status": "failed"}),
            stored_reply(value={**stored(), "collection": "elsewhere"}),
            stored_reply(value={**stored(), "document": "two"}),
            stored_reply(value={**stored(), "etag": "f" * 16}),
            stored_reply(value={**stored(), "revision": "f" * 16}),
            stored_reply(value=b'{"status":"stored","status":"stored"}'),
            wire.frame(b'{"x":"\xff"}', status=201),
            stored_reply(code=200),
            stored_reply(code=202),
            wire.frame(b"{}", status=201, length=99),
            stored_reply().replace(
                b"Content-Length:", b"Transfer-Encoding: chunked\r\nContent-Length:"
            ),
            stored_reply().replace(b"ETag:", b'ETag: "0000000000000000"\r\nETag:'),
        ]
        source = b"# original\r\nn: 9007199254740993\r\n"
        for response in variants:
            with (
                self.subTest(response=response),
                Peer(lambda req, response=response: response) as peer,
            ):
                p = self.bad([(peer.port, 1)], "put", source, uncertain=1, CPP_CREATE_ONLY=1)
                envelope = p.stdout.split(b"\n", 6)
                self.assertRegex(envelope[0], rb"^[0-9a-f]{32}$")
                self.assertNotEqual(envelope[0], b"0" * 32)
                self.assertEqual(
                    envelope[1:],
                    [b"PUT", b"/v1/collections/examples/documents/one", b"", b"1", b"1", source],
                )
                self.assertEqual(
                    peer.mutations()[0][2]["X-Yamora-Request-Id"].encode(), envelope[0]
                )

    def test_receipt_integer_and_condition_status_contracts(self):
        for count in (True, 1.0, "1", 0, 2**64):
            with (
                self.subTest(count=count),
                Peer(
                    lambda req, count=count: reply(
                        {"status": "committed", "revision": REV, "operations": count}
                    )
                ) as peer,
            ):
                self.bad(
                    [(peer.port, 1)],
                    "transaction",
                    b'{"operations":[{"collection":"examples","document":"one","delete":true}]}',
                    uncertain=1,
                )
        with Peer(lambda req: stored_reply()) as peer:
            self.bad([(peer.port, 1)], "put", b"n: 1\n", CPP_ETAG=REV, uncertain=1)
            self.good([(peer.port, 1)], "put", b"n: 1\n")
        with Peer(lambda req: wire.frame(b"x", status=204)) as peer:
            self.bad([(peer.port, 1)], "erase", uncertain=1)

    def test_mutable_inputs_recovery_and_prior_uncertainty_survives_rejection(self):
        with Peer(lambda req: stored_reply(value={**stored(), "status": "bad"})) as peer:

            def receipt_once(req):
                return (
                    stored_reply(value={**stored(), "status": "bad"})
                    if len(peer.mutations()) == 1
                    else stored_reply()
                )

            peer.handle = receipt_once
            source = b"# frozen\r\nn: 1\r\n"
            self.good(
                [(peer.port, 1)], "recover", source, CPP_CREATE_ONLY=1, CPP_REQUEST_ID="a" * 32
            )
            self.assertEqual(peer.mutations()[0], peer.mutations()[1])
            self.assertEqual(peer.mutations()[0][3], source)
        for first in (503, 408, 500, 307):
            with self.subTest(first=first), Peer() as peer:

                def reject(req, first=first):
                    return reply(
                        b"private remote detail", first if len(peer.mutations()) == 1 else 412
                    )

                peer.handle = reject
                mode = "prepared" if first == 503 else "recover"
                p = self.bad(
                    [(peer.port, 1)],
                    mode,
                    b"n: 1\n",
                    uncertain=1,
                    code=412,
                    CPP_REQUEST_ID="b" * 32,
                )
                self.assertEqual(p.stdout.splitlines()[0], b"b" * 32)
                self.assertEqual(peer.mutations()[0], peer.mutations()[1])
        with Peer(lambda req: reply(b"{}", 412)) as peer:
            self.bad([(peer.port, 1)], "put", b"n: 1\n", code=412, uncertain=0)

    def test_deadline_cancel_and_concurrent_isolation(self):
        with Peer() as peer:
            peer.metadata = lambda req: (peer.stop.wait(0.25), reply(status()))[1]
            start = time.monotonic()
            self.bad([(peer.port, 1)], kind=5, CPP_TIMEOUT=80)
            self.assertLess(time.monotonic() - start, 0.5)
            self.bad([(peer.port, 1)], kind=4, CPP_CANCELLED=1)
        for isolated in (False, True):
            with self.subTest(isolated=isolated), Peer() as peer:
                arrived, release = threading.Event(), threading.Event()

                def block(req, isolated=isolated, arrived=arrived, release=release):
                    if len(peer.mutations()) >= (6 if isolated else 1):
                        arrived.set()
                    if not release.wait(5):
                        raise AssertionError("test did not release requests")
                    return stored_reply(code=200)

                peer.handle = block
                with self.controlled(
                    [(peer.port, 1)],
                    "isolation" if isolated else "patch",
                    CPP_BODY='{"$inc":{"n":1}}',
                    CPP_REQUEST_ID="e" * 32,
                ) as p:
                    self.assertTrue(arrived.wait(5), "operations did not overlap")
                    p.stdin.write(b"cancel\n")
                    p.stdin.flush()
                    time.sleep(0.04)
                    release.set()
                    out, err = p.communicate(timeout=5)
                    if isolated:
                        self.assertEqual(p.returncode, 0, err)
                    else:
                        self.assertEqual(p.returncode, 2, err)
                        self.assertEqual(err.splitlines()[0], b"4 0 1")
                        self.assertEqual(out.splitlines()[0], b"e" * 32)

    @contextlib.contextmanager
    def shared_prepared_process(self, peer, **extra):
        p = subprocess.Popen(
            [PROBE, "shared-rejection"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=settings(
                [(peer.port, 1)],
                CPP_REQUEST_ID="7" * 32,
                CPP_CREATE_ONLY=1,
                CPP_ATTEMPT_TIMEOUT=8000,
                CPP_TIMEOUT=15000,
                **extra,
            ),
        )
        try:
            p.stdin.write(b"# same envelope\r\nn: 1\r\n")
            p.stdin.close()
            p.stdin = None
            yield p
        finally:
            if p.poll() is None:
                p.kill()
            p.communicate(timeout=5)

    def observe_ambiguity(self, process):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(8), "first execution did not report ambiguity")
        self.assertEqual(process.stdout.readline(), b"AMBIGUOUS\n")
        self.assertIsNone(process.poll(), "second execution must still be in flight")

    def test_shared_prepared_uncertainty_precedes_rejection(self):
        for rejection in (401, 412):
            with self.subTest(rejection=rejection), Peer() as peer:
                lock = threading.Lock()
                both = threading.Event()
                release = threading.Event()
                mutations = []

                def handle(
                    req,
                    both=both,
                    release=release,
                    lock=lock,
                    mutations=mutations,
                    rejection=rejection,
                ):
                    with lock:
                        mutations.append(req)
                        position = len(mutations)
                        if position == 2:
                            both.set()
                    if not both.wait(8):
                        raise AssertionError("same envelope calls did not overlap")
                    if position == 1:
                        return reply(b"{}", 307)
                    if not release.wait(8):
                        raise AssertionError("definitive rejection was never released")
                    return reply(b"{}", rejection)

                peer.handle = handle
                with self.shared_prepared_process(peer, CPP_SHARED_STATUS=rejection) as process:
                    try:
                        self.assertTrue(both.wait(8))
                        self.observe_ambiguity(process)
                        # Both calls entered execute while the envelope was still
                        # certain. Only now allow the second call's rejection.
                        release.set()
                        out, err = process.communicate(timeout=8)
                        self.assertEqual(process.returncode, 0, (out, err))
                        self.assertEqual(mutations[0], mutations[1])
                    finally:
                        release.set()

    def test_shared_prepared_uncertainty_precedes_discovery_allocation(self):
        with Peer() as peer:
            lock = threading.Lock()
            blocked = threading.Event()
            release = threading.Event()
            discoveries = []

            def metadata(req):
                with lock:
                    discoveries.append(req)
                    position = len(discoveries)
                if position == 1:
                    return reply(status())
                blocked.set()
                if not release.wait(8):
                    raise AssertionError("discovery allocation fault was never released")
                return reply({**status(), "diagnostic": "validation-fault"})

            def ambiguous(req):
                if not blocked.wait(8):
                    raise AssertionError("other execution never entered discovery")
                return reply(b"{}", 307)

            peer.metadata, peer.handle = metadata, ambiguous
            with self.shared_prepared_process(
                peer, CPP_SHARED_STATUS=0, CPP_DECODE_FAULT="concurrent-allocation"
            ) as process:
                try:
                    self.assertTrue(blocked.wait(8))
                    self.observe_ambiguity(process)
                    release.set()
                    out, err = process.communicate(timeout=8)
                    self.assertEqual(process.returncode, 0, (out, err))
                    self.assertEqual(
                        len(peer.mutations()),
                        1,
                        "allocation-failing execution must remain undispatched",
                    )
                finally:
                    release.set()

    def test_invalid_json_and_transaction_shapes_before_io(self):
        bodies = [
            b'{"operations":[]}',
            b'{"operations":true}',
            b'{"operations":[{"collection":"examples","document":"one","delete":1}]}',
            b'{"operations":[{"collection":"examples","document":"one","delete":true,"put":"n: 1"}]}',
            b'{"operations":[{"collection":"examples","document":"one","delete":true},{"collection":"examples","document":"one","delete":true}]}',
            b'{"operations":[],"\\u006fperations":[]}',
            b'{"operations":NaN}',
            b"{} junk",
            b'{"n":01}',
            b'{"n":"\\ud800"}',
        ]
        with Peer() as peer:
            for body in bodies:
                with self.subTest(body=body):
                    self.bad([(peer.port, 1)], "transaction", body, kind=0)
            self.assertEqual(peer.requests, [])

    def test_public_decoding_and_allocation_faults_keep_recovery(self):
        for fault, kind in [("cancel", 4), ("deadline", 5), ("allocation", 6)]:
            with (
                self.subTest(fault=fault),
                Peer(lambda req: stored_reply(value=stored(document="validation-fault"))) as peer,
            ):
                p = self.bad(
                    [(peer.port, 1)],
                    "put",
                    b"# immutable\r\nn: 1\r\n",
                    document="validation-fault",
                    CPP_DECODE_FAULT=fault,
                    CPP_TIMEOUT=350,
                    uncertain=1,
                    kind=kind,
                )
                fields = p.stdout.split(b"\n", 6)
                self.assertEqual(fields[2], b"/v1/collections/examples/documents/validation-fault")
                self.assertEqual(fields[6], b"# immutable\r\nn: 1\r\n")
                self.assertEqual(fields[0].decode(), peer.mutations()[0][2]["X-Yamora-Request-Id"])
        for fault, kind in [("cancel", 4), ("deadline", 5)]:
            with (
                self.subTest(read_fault=fault),
                Peer(lambda req: reply({"probe": "validation-fault"})) as peer,
            ):
                self.bad([(peer.port, 1)], CPP_DECODE_FAULT=fault, CPP_TIMEOUT=250, kind=kind)
        with Peer() as peer:
            self.bad(
                [(peer.port, 1)],
                "patch",
                b'{"$set":{"note":"validation-fault"}}',
                CPP_DECODE_FAULT="cancel",
                kind=4,
            )
            self.assertEqual(peer.requests, [])

    def test_cached_binding_is_revalidated_on_the_same_client(self):
        with Peer() as peer:
            p = subprocess.Popen(
                [PROBE, "twice"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=settings([(peer.port, 1)], CPP_TIMEOUT=200),
            )
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(p.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5))
                self.assertEqual(p.stdout.readline(), b"FIRST\n")
                peer.feed = reply({**checkpoint(), "checkpoint": f"v1.{'d' * 32}.{'0' * 16}"})
                out, err = p.communicate(b"next\n", timeout=5)
                self.assertEqual(p.returncode, 2, (out, err))
                self.assertEqual(len([r for r in peer.requests if r[1] == "/healthz"]), 1)
            finally:
                if p.poll() is None:
                    p.kill()
                p.communicate(timeout=5)

    def test_call_inputs_are_snapshotted_before_discovery(self):
        reached, release = threading.Event(), threading.Event()
        with Peer(lambda req: stored_reply()) as peer:

            def block(req):
                reached.set()
                if not release.wait(5):
                    raise AssertionError("discovery snapshot barrier timed out")
                return reply(status())

            peer.metadata = block
            source = "# mutable caller\r\nn: 1\r\n"
            with self.controlled(
                [(peer.port, 1)],
                "put",
                CPP_BODY=source,
                CPP_MUTATE=1,
                CPP_CREATE_ONLY=1,
                CPP_REQUEST_ID="9" * 32,
            ) as p:
                try:
                    self.assertTrue(reached.wait(5))
                    p.stdin.write(b"mutate\n")
                    p.stdin.flush()
                    self.assertEqual(p.stdout.readline(), b"MUTATED\n")
                    release.set()
                    out, err = p.communicate(timeout=5)
                    self.assertEqual(p.returncode, 0, (out, err))
                finally:
                    release.set()
            mutation = peer.mutations()[0]
            self.assertEqual(mutation[3], source.encode())
            self.assertEqual(mutation[2]["X-Yamora-Request-Id"], "9" * 32)
            self.assertEqual(mutation[2]["If-None-Match"], "*")
            self.assertNotIn("If-Match", mutation[2])


class NativeIntervals:
    """Observe complete native sends and immediately consumed framed responses.

    Synchronize connected sockets before sending; never hold response reads.
    Holding gateway replies later must not inflate these native intervals.
    """

    def __init__(self, mode=None):
        self.mode = mode
        self.ready = threading.Barrier(6)
        self.lock = threading.Lock()
        self.serial = threading.Lock()
        self.first_complete = threading.Event()
        self.records = []

    def before_send(self, connection, request):
        with self.lock:
            record = {
                "ordinal": len(self.records),
                "socket": connection.sock.fileno(),
                "id": request[2]["X-Yamora-Request-Id"],
            }
            self.records.append(record)
        self.ready.wait(6)
        if self.mode == "early-completed" and record["ordinal"]:
            if not self.first_complete.wait(6):
                raise AssertionError("first native response did not complete")
        if self.mode == "serialized":
            if not self.serial.acquire(timeout=6):
                raise AssertionError("serialized native exchange timed out")
            record["serial_owned"] = True
        return record

    def sent(self, record):
        record["sent"] = time.monotonic_ns()

    def completed(self, record):
        record["completed"] = time.monotonic_ns()
        if not record["ordinal"]:
            self.first_complete.set()

    def release(self, record):
        if record.get("serial_owned"):
            self.serial.release()

    def require_overlap(self):
        if len(self.records) != 6 or len({r["socket"] for r in self.records}) != 6:
            raise AssertionError("six independent native connections required")
        if not all("sent" in r and "completed" in r for r in self.records):
            raise AssertionError("six complete native exchanges required")
        if max(r["sent"] for r in self.records) >= min(r["completed"] for r in self.records):
            raise AssertionError("native send/response intervals did not overlap")


class NativeCluster:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="native-", dir=wire.ROOT.name))
        self.nodes = []
        self.reservations = []
        self.seeds = [(self.reserve(), i + 1) for i in range(3)]
        peers = [
            {
                "id": i + 1,
                "name": f"node{i + 1}.test",
                "address": "127.0.0.1",
                "port": self.reserve(),
            }
            for i in range(3)
        ]
        for name, text in [("read", wire.READ), ("write", wire.WRITE)]:
            p = self.root / f"{name}.token"
            p.write_text(text)
            p.chmod(0o600)
        for i in range(3):
            data, journal = self.root / f"data{i}", self.root / f"journal{i}"
            data.mkdir(mode=0o700)
            journal.mkdir(mode=0o700)
            spec = {
                "cluster": CLUSTER,
                "node": i + 1,
                "journal_dir": str(journal),
                "peers": peers,
                "peer_tls": {
                    "cert_file": str(wire.CERTS / f"node{i + 1}.pem"),
                    "key_file": str(wire.CERTS / f"node{i + 1}.key"),
                    "ca_file": str(wire.CERTS / "ca.pem"),
                },
                "request_timeout_ms": 2500,
                "journal_cache_bytes": 1048576,
            }
            config = self.root / f"config{i}.json"
            config.write_text(json.dumps(spec))
            config.chmod(0o600)
            args = [
                BINARY,
                "--data-dir",
                str(data),
                "--port",
                str(self.seeds[i][0]),
                "--workers",
                "6",
                "--cluster-config-file",
                str(config),
                "--auth-token-file",
                str(self.root / "read.token"),
                "--write-auth-token-file",
                str(self.root / "write.token"),
                "--cache-bytes",
                "1048576",
                "--tls-cert-file",
                str(wire.CERTS / "server.pem"),
                "--tls-key-file",
                str(wire.CERTS / "server.key"),
                "--tls-client-ca-file",
                str(wire.CERTS / "ca.pem"),
                "--io-timeout-ms",
                "3000",
            ]
            self.nodes.append({"args": args, "process": None, "log": self.root / f"node{i}.log"})
        for reservation in self.reservations:
            reservation.close()
        self.reservations.clear()
        try:
            for i in range(3):
                self.start(i)
            self.leader()
        except BaseException:
            self.close()
            raise

    def reserve(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if port == 8000:
            raise RuntimeError("owner port")
        self.reservations.append(sock)
        return port

    def start(self, index):
        node = self.nodes[index]
        if node["process"] is not None:
            raise RuntimeError("already running")
        with node["log"].open("a+") as log:
            p = subprocess.Popen(node["args"], stdout=subprocess.PIPE, stderr=log)
        node["process"] = p
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            if not selector.select(15):
                raise AssertionError("native startup timeout")
        banner = p.stdout.readline()
        if not banner.startswith(f"yamora listening on 127.0.0.1:{self.seeds[index][0]} ".encode()):
            raise AssertionError(f"native startup failed: {banner!r}; {node['log'].read_text()}")

    def stop(self, index, crash=False):
        node = self.nodes[index]
        p = node["process"]
        if p is None:
            return
        try:
            p.kill() if crash else p.terminate()
            try:
                code = p.wait(8)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(5)
                raise AssertionError("native stop timed out") from None
            if code != (-9 if crash else 0):
                raise AssertionError(f"native failed: {code}; {node['log'].read_text()}")
        finally:
            p.stdout.close()
            node["process"] = None
        text = node["log"].read_text()
        if re.search(r"AddressSanitizer|LeakSanitizer|runtime error:", text):
            raise AssertionError(text)

    def close(self):
        errors = []
        for i in range(3):
            try:
                self.stop(i)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def exchange(self, index, request, timeout=3, intervals=None):
        method, path, headers, body = request
        context = ssl.create_default_context(cafile=str(wire.CERTS / "ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(wire.CERTS / "client.pem", wire.CERTS / "client.key")
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.seeds[index][0], context=context, timeout=timeout
        )
        record = None
        try:
            if intervals is not None:
                connection.connect()
                record = intervals.before_send(connection, request)
            connection.request(method, path, body=body, headers=headers)
            if intervals is not None:
                intervals.sent(record)
            response = connection.getresponse()
            value = response.read()
            if intervals is not None:
                intervals.completed(record)
            raw = (
                f"HTTP/1.1 {response.status} Native\r\n".encode()
                + b"".join(f"{k}: {v}\r\n".encode() for k, v in response.getheaders())
                + b"\r\n"
                + value
            )
            return response.status, value, raw
        finally:
            if record is not None:
                intervals.release(record)
            connection.close()

    def read(self, index, path):
        return self.exchange(index, ("GET", path, {"Authorization": f"Bearer {wire.READ}"}, b""))

    def leader(self):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            for index, node in enumerate(self.nodes):
                if node["process"] is None:
                    continue
                try:
                    code, body, _ = self.read(index, "/v1/cluster/status")
                    if code == 200 and json.loads(body)["role"] == "leader":
                        return index
                except (OSError, http.client.HTTPException):
                    pass
            time.sleep(0.025)
        raise AssertionError("native leader election failed")


class NativeAcceptance(Helpers):
    def overlapping_patches(self, cluster, distinct, mode=None):
        target = cluster.leader()
        arrivals = threading.Event()
        release_dispatch = threading.Event()
        responses = threading.Event()
        release_response = threading.Event()
        lock = threading.Lock()
        pending = []
        upstream = []
        intervals = NativeIntervals(mode)
        with Peer(node=target + 1) as gateway:

            def barrier(
                req,
                target=target,
                lock=lock,
                pending=pending,
                arrivals=arrivals,
                release_dispatch=release_dispatch,
                upstream=upstream,
                responses=responses,
                intervals=intervals,
                release_response=release_response,
            ):
                if req[0] != "PATCH":
                    return cluster.exchange(target, req)[2]
                with lock:
                    pending.append(req)
                    if len(pending) == 6:
                        arrivals.set()
                if not release_dispatch.wait(8):
                    raise AssertionError("dispatch barrier timeout")
                result = cluster.exchange(target, req, timeout=8, intervals=intervals)
                with lock:
                    upstream.append(result)
                    if len(upstream) == 6:
                        responses.set()
                if not release_response.wait(8):
                    raise AssertionError("response barrier timeout")
                return result[2]

            gateway.metadata = barrier
            gateway.feed = barrier
            gateway.handle = barrier
            p = subprocess.Popen(
                [PROBE, "parallel"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=settings(
                    [(gateway.port, target + 1)],
                    CPP_DISTINCT=int(distinct),
                    CPP_REQUEST_ID="2" * 32,
                    CPP_TIMEOUT=20000,
                    CPP_ATTEMPT_TIMEOUT=8000,
                ),
            )
            try:
                p.stdin.write(b'{"$inc":{"n":1}}')
                p.stdin.close()
                p.stdin = None
                self.assertTrue(arrivals.wait(8), "six requests must overlap BEFORE dispatch")
                self.assertIsNone(p.poll())
                self.assertEqual(
                    len({r[2]["X-Yamora-Request-Id"] for r in pending}),
                    6 if distinct else 1,
                )
                release_dispatch.set()
                self.assertTrue(
                    responses.wait(8), "six native receipts must overlap BEFORE release"
                )
                intervals.require_overlap()
                self.assertIsNone(p.poll())
                self.assertTrue(all(r[0] == 200 for r in upstream))
                if not distinct:
                    self.assertEqual(len({r[1] for r in upstream}), 1)
                release_response.set()
                out, err = p.communicate(timeout=8)
                self.assertEqual(p.returncode, 0, (out, err))
            finally:
                release_dispatch.set()
                release_response.set()
                if p.poll() is None:
                    p.kill()
                p.communicate(timeout=5)
        return upstream[0][1]

    def test_overlap_guard_rejects_serial_and_early_completed_native_replies(self):
        for distinct in (False, True):
            for mode in ("serialized", "early-completed"):
                with self.subTest(distinct=distinct, mode=mode):
                    cluster = NativeCluster()
                    try:
                        self.good(
                            cluster.seeds,
                            "put",
                            b"n: 0\n",
                            CPP_CREATE_ONLY=1,
                            CPP_REQUEST_ID="1" * 32,
                        )
                        with self.assertRaisesRegex(
                            AssertionError, "native send/response intervals"
                        ):
                            self.overlapping_patches(cluster, distinct, mode)
                    finally:
                        cluster.close()

    def test_native_three_node_failover_replay_overlap_quorum_and_restart(self):
        cluster = NativeCluster()
        try:
            seeds = cluster.seeds
            source = "# authored café\r\nname: Alpha\r\nn: 0 # retain\r\nwide: 9223372036854775807\r\n".encode()
            original = self.good(seeds, "put", source, CPP_CREATE_ONLY=1, CPP_REQUEST_ID="1" * 32)
            self.assertEqual(self.good(seeds, "get")[3], source)
            self.bad(
                seeds, CPP_CERT="", CPP_KEY="", CPP_TIMEOUT=200, CPP_ATTEMPT_TIMEOUT=80, kind=5
            )
            self.assertEqual(
                json.loads(self.good(seeds, "query", b'{"count_only":true}')[3])["matched"], 1
            )
            self.assertEqual(
                json.loads(self.good(seeds, "query", b"{}")[3])["documents"][0]["value"]["wide"],
                9223372036854775807,
            )
            self.assertEqual(json.loads(self.good(seeds, "documents")[3])["documents"], ["one"])
            self.bad(seeds, "patch", b'{"$inc":{"n":1}}', code=412, CPP_ETAG="0" * 16)
            initial = json.loads(self.good(seeds, "changes")[3])["checkpoint"]
            old = cluster.leader()
            saved = []
            mutations = []
            premature = []
            verified = threading.Event()
            order_lock = threading.Lock()
            # Every configured endpoint is observed. There is no direct native
            # seed through which a timeout retry could bypass the proof gate.
            with contextlib.ExitStack() as stack:
                gateways = [stack.enter_context(Peer(node=i + 1)) for i in range(3)]

                def forward(index, req):
                    mutation = req[0] in ("PUT", "PATCH", "DELETE") or req[1] == "/v1/transactions"
                    first = False
                    if mutation:
                        with order_lock:
                            first = not mutations
                            mutations.append((index, req))
                            if not first and not verified.is_set():
                                premature.append(index + 1)
                                return reply(b"{}", 503)
                    if verified.is_set() and index == old:
                        return reply(b"{}", 503)
                    result = cluster.exchange(index, req)
                    if mutation and first:
                        self.assertEqual(index, old)
                        self.assertEqual(result[0], 200)
                        committed = json.loads(result[1])
                        self.assertEqual(committed["status"], "stored")
                        self.assertEqual(
                            (committed["collection"], committed["document"]), ("examples", "one")
                        )
                        # The entire seed allowset stays observed until BOTH the
                        # original receipt and exact source have been verified.
                        actual = cluster.read(old, "/v1/collections/examples/documents/one")
                        self.assertEqual(actual[0], 200)
                        self.assertEqual(actual[1], source.replace(b"n: 0", b"n: 1"))
                        with order_lock:
                            saved.append((req, result))
                            verified.set()
                        cluster.stop(old, crash=True)
                        return None
                    return result[2]

                for index, gateway in enumerate(gateways):

                    def handler(req, index=index):
                        return forward(index, req)

                    gateway.metadata = gateway.feed = gateway.handle = handler
                observed_seeds = [
                    (gateways[old].port, old + 1),
                    *[
                        (gateway.port, index + 1)
                        for index, gateway in enumerate(gateways)
                        if index != old
                    ],
                ]
                recovered = self.good(
                    observed_seeds,
                    "patch",
                    b'{"$inc":{"n":1}}',
                    CPP_TIMEOUT=20000,
                    # Two bounded 3s upstream exchanges fit inside this cap.
                    # A delayed proof can never silently pass: every premature
                    # mutation attempt is counted and fails acceptance below.
                    CPP_ATTEMPT_TIMEOUT=8000,
                )
                self.assertTrue(verified.is_set())
                self.assertEqual(
                    premature,
                    [],
                    f"mutation retries before receipt/source verification at seeds {premature}",
                )
                self.assertGreaterEqual(len(mutations), 2, "lost reply did not cause a retry")
                original_request = saved[0][0]
                for _, retried in mutations:
                    self.assertEqual(
                        (retried[0], retried[1], retried[3]),
                        (original_request[0], original_request[1], original_request[3]),
                    )
                    for header in ("X-Yamora-Request-Id", "If-Match", "If-None-Match"):
                        self.assertEqual(retried[2].get(header), original_request[2].get(header))
                self.assertEqual(recovered[3], saved[0][1][1])
                lost_id = original_request[2]["X-Yamora-Request-Id"]
                self.assertRegex(lost_id, r"^[0-9a-f]{32}$")
            self.assertEqual(
                self.good(seeds, "get", CPP_TIMEOUT=12000)[3], source.replace(b"n: 0", b"n: 1")
            )
            frames = json.loads(self.good(seeds, "changes", CPP_AFTER=initial)[3])["transactions"]
            self.assertEqual(
                sum(o["document"] == "one" for f in frames for o in f["operations"]), 1
            )
            cluster.start(old)
            same = self.overlapping_patches(cluster, False)
            self.overlapping_patches(cluster, True)
            exact = source.replace(b"n: 0", b"n: 8")
            self.assertEqual(self.good(seeds, "get")[3], exact)
            txbody = b'{"operations":[{"collection":"examples","document":"two","put":"# tx\\r\\nn: 9\\r\\n","create_only":true}]}'
            tx = self.good(seeds, "transaction", txbody, CPP_REQUEST_ID="3" * 32)
            page = self.good(seeds, "documents", CPP_LIMIT=1)
            first = json.loads(page[3])
            self.assertEqual(first["documents"], ["one"])
            second = self.good(
                seeds, "documents", CPP_LIMIT=1, CPP_AFTER=first["next_after"], CPP_REVISION=page[1]
            )
            self.assertEqual(json.loads(second[3])["documents"], ["two"])
            definitions = b'{"indexes":[{"collection":"examples","name":"words","fields":["$source"],"type":"text"}]}'
            catalog = self.good(seeds, "set_indexes", definitions, CPP_REQUEST_ID="4" * 32)
            self.assertEqual(
                json.loads(self.good(seeds, "search", b'{"index":"words","text":"Alpha"}')[3])[
                    "documents"
                ][0]["id"],
                "one",
            )
            self.assertEqual(
                json.loads(
                    self.good(
                        seeds, "aggregate", b'{"pipeline":[{"$group":{"_id":null,"n":{"$sum":1}}}]}'
                    )[3]
                )["documents"][0]["n"],
                2,
            )
            deleted = self.good(seeds, "erase", document="two", CPP_REQUEST_ID="5" * 32)
            self.good(seeds, "put", b"n: 10\n", document="two")
            for mode, body, extra in [
                ("start_index_build", b'{"indexes":[]}', {}),
                ("index_build", b"", {}),
                ("replication_status", b"", {}),
                ("replication_begin", b"{}", {}),
            ]:
                self.bad(seeds, mode, body, kind=0, code=0, **extra)
            code, body, _ = cluster.read(cluster.leader(), "/v1/changes/stream")
            self.assertEqual(code, 400)
            self.assertEqual(json.loads(body), {"error": "invalid_change_stream"})
            leader = cluster.leader()
            for i in range(3):
                if i != leader:
                    cluster.stop(i)
            start = time.monotonic()
            self.bad(
                seeds,
                "put",
                b"n: 99\n",
                document="quorum",
                CPP_REQUEST_ID="6" * 32,
                CPP_TIMEOUT=350,
                CPP_ATTEMPT_TIMEOUT=100,
                kind=5,
                uncertain=0,
            )
            self.assertLess(time.monotonic() - start, 1.2)
            cluster.stop(leader)
            for i in range(3):
                cluster.start(i)
            cluster.leader()
            self.assertEqual(self.good(seeds, "get")[3], exact)
            self.assertEqual(
                self.good(seeds, "put", source, CPP_CREATE_ONLY=1, CPP_REQUEST_ID="1" * 32),
                original,
            )
            self.assertEqual(
                self.good(seeds, "patch", b'{"$inc":{"n":1}}', CPP_REQUEST_ID=lost_id)[3],
                recovered[3],
            )
            self.assertEqual(
                self.good(seeds, "patch", b'{"$inc":{"n":1}}', CPP_REQUEST_ID="2" * 32)[3], same
            )
            self.assertEqual(self.good(seeds, "transaction", txbody, CPP_REQUEST_ID="3" * 32), tx)
            self.assertEqual(
                self.good(seeds, "set_indexes", definitions, CPP_REQUEST_ID="4" * 32), catalog
            )
            self.assertEqual(
                self.good(seeds, "erase", document="two", CPP_REQUEST_ID="5" * 32), deleted
            )
            self.assertEqual(self.good(seeds, "get", document="two")[3], b"n: 10\n")
            self.assertEqual(self.good(seeds, "get")[3], exact)
        finally:
            cluster.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
