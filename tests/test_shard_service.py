"""Real native shard RPC, storage, authorization and restart qualification.

The fixture callbacks use native prepared transactions; it is intentionally
separate from actual Raft/independent-host availability qualification.
"""

import hashlib
import io
import json
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import unittest
from pathlib import Path

from tools.shared.scratch import temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class NativeShardServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = temporary_directory(prefix="yamora-shard-service-build-")
        cls.directory = cls.temporary.__enter__()
        cls.addClassCleanup(cls.temporary.__exit__, None, None, None)
        cls.binary = cls.directory / "shard-service"
        makefile = (ROOT / "Makefile").read_text().replace("\\\n", " ")
        sources = re.search(r"^LIB_SOURCE := (.+)$", makefile, re.MULTILINE).group(1).split()
        sources += [
            "tests/shard_service_harness.c",
            "src/transport/tls.c",
            "src/transport/shard_rpc.c",
            "src/security/access.c",
            "src/security/oidc.c",
            "src/security/oidc_json.c",
            "src/security/field_policy.c",
            "src/security/field_policy_query.c",
            "src/sharding/routing.c",
            "src/sharding/control.c",
            "src/sharding/native.c",
            "src/sharding/router.c",
            "src/sharding/cursor.c",
            "src/sharding/aggregate.c",
            "src/sharding/service.c",
            "src/sharding/service_apply.c",
        ]
        sanitized = os.environ.get("SHARD_SERVICE_SANITIZED") == "1"
        sanitizer_flags = (
            [
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=undefined",
            ]
            if sanitized
            else []
        )
        build = subprocess.run(
            [
                "clang" if sanitized else os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                *sanitizer_flags,
                *[str(ROOT / source) for source in dict.fromkeys(sources)],
                "-o",
                str(cls.binary),
                "-pthread",
                "-lssl",
                "-lcrypto",
                "-lyaml",
                "-lm",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)

        def openssl(*args):
            subprocess.run(
                ["openssl", *map(str, args)], check=True, capture_output=True, timeout=20
            )

        for ca in ("trusted", "foreign"):
            openssl(
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                cls.directory / f"{ca}.key",
                "-out",
                cls.directory / f"{ca}.pem",
                "-days",
                "1",
                "-subj",
                f"/CN={ca}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            )
        for serial, name in enumerate(("control", "alpha", "beta", "stranger", "foreign-node"), 1):
            ca = "foreign" if name == "foreign-node" else "trusted"
            openssl(
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                cls.directory / f"{name}.key",
                "-out",
                cls.directory / f"{name}.csr",
                "-subj",
                f"/CN={name}.test",
            )
            extension = cls.directory / f"{name}.ext"
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{name}.test\n"
            )
            openssl(
                "x509",
                "-req",
                "-in",
                cls.directory / f"{name}.csr",
                "-CA",
                cls.directory / f"{ca}.pem",
                "-CAkey",
                cls.directory / f"{ca}.key",
                "-set_serial",
                serial,
                "-out",
                cls.directory / f"{name}.pem",
                "-days",
                "1",
                "-extfile",
                extension,
            )
            (cls.directory / f"{name}.key").chmod(0o600)

    def setUp(self):
        self.work = temporary_directory(prefix="yamora-shard-service-data-")
        self.root = self.work.__enter__()
        self.addCleanup(self.work.__exit__, None, None, None)
        self.ports = []
        for _ in range(3):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                self.ports.append(listener.getsockname()[1])
        self.configs = []
        for i, name in enumerate(("control", "alpha", "beta")):
            (self.root / f"data{i}").mkdir()
            config = self.root / f"config{i}.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "local_name": f"{name}.test",
                        "local_group": name,
                        "control_group": "control",
                        "listen": {"address": "127.0.0.1", "port": self.ports[i]},
                        "peer_tls": {
                            "cert_file": str(self.directory / f"{name}.pem"),
                            "key_file": str(self.directory / f"{name}.key"),
                            "ca_file": str(self.directory / "trusted.pem"),
                        },
                        "peers": [
                            {
                                "group": peer,
                                "name": f"{peer}.test",
                                "address": "127.0.0.1",
                                "port": self.ports[j],
                            }
                            for j, peer in enumerate(("control", "alpha", "beta"))
                        ],
                        "request_timeout_ms": 1200,
                    }
                )
            )
            config.chmod(0o600)
            self.configs.append(config)
        self.process = None
        self.addCleanup(self.stop)
        self.start()

    def start(self):
        self.process = subprocess.Popen(
            [str(self.binary), str(self.root), *map(str, self.configs)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertTrue(
            select.select([self.process.stdout], [], [], 15)[0], "native service did not start"
        )
        line = self.process.stdout.readline()
        if line != "ready\n":
            _, error = self.process.communicate(timeout=5)
            self.fail((line, error))

    def stop(self):
        if self.process is None:
            return
        process, self.process = self.process, None
        process.stdin.close()
        process.wait(timeout=10)
        error = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(process.returncode, 0, error)

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()
        self.assertTrue(
            select.select([self.process.stdout], [], [], 20)[0], "request deadline exceeded"
        )
        return json.loads(self.process.stdout.readline())

    def request(self, target, body=None, credential="Bearer writer", method="POST", expected=200):
        reply = self.send(
            {
                "credential": credential,
                "method": method,
                "target": target,
                "body": json.dumps(body) if body is not None else "",
            }
        )
        self.assertEqual(reply["status"], expected, reply)
        return json.loads(reply["body"])

    def install(self):
        self.request(
            "/v1/sharding/install",
            {
                "version": 1,
                "key_version": 1,
                "algorithm": "sha256-64be-v1",
                "placement_id": "a" * 32,
                "collection": "docs",
                "epoch": 1,
                "field": "tenant",
                "ranges": [
                    {
                        "first": "0000000000000000",
                        "last": "7fffffffffffffff",
                        "shard": "left",
                        "group": "alpha",
                    },
                    {
                        "first": "8000000000000000",
                        "last": "ffffffffffffffff",
                        "shard": "right",
                        "group": "beta",
                    },
                ],
            },
        )

    def route(
        self, operation, key=1, docid="one", source=None, epoch=1, mutation_id=None, **kwargs
    ):
        body = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": epoch,
            "operation": operation,
            "key": key,
            "id": docid,
            "mutation_id": mutation_id or f"write-{docid}",
        }
        if source is not None:
            body["source"] = source
        return self.request("/v1/sharding/route", body, **kwargs)

    def state(self):
        return self.request("/v1/sharding?collection=docs", method="GET")

    def raw(
        self,
        *,
        identity="alpha",
        claimed="alpha.test",
        credential="Bearer reader",
        payload=b"docs",
        kind=1,
        destination=0,
        protocols=("yamora-shard/1",),
    ):
        context = ssl.create_default_context(cafile=str(self.directory / "trusted.pem"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(list(protocols))
        if identity:
            context.load_cert_chain(
                self.directory / f"{identity}.pem", self.directory / f"{identity}.key"
            )
        header = bytearray(48)
        header[:6] = b"YSR1\x01" + bytes([kind])
        struct.pack_into(">IIII", header, 8, 0, len(claimed), len(credential), len(payload))
        header[24:40] = bytes(range(16))
        received = bytearray()
        try:
            with socket.create_connection(("127.0.0.1", self.ports[destination]), timeout=3) as raw:
                with context.wrap_socket(
                    raw, server_hostname=("control", "alpha", "beta")[destination] + ".test"
                ) as conn:
                    conn.settimeout(3)
                    conn.sendall(header + claimed.encode() + credential.encode() + payload)
                    while block := conn.recv(65536):
                        received.extend(block)
        except (ssl.SSLError, ConnectionError, socket.timeout):
            pass
        return bytes(received)

    def test_held_scan_requires_fresh_proof_and_keeps_its_original_view(self):
        self.install()
        keys = [
            key
            for key in range(20)
            if hashlib.sha256(b"YSK\x01\x02\x00\x08" + key.to_bytes(8, "big")).digest()[0] < 128
        ][:3]
        self.assertEqual(len(keys), 3)
        sources = {f"doc{i}": f"tenant: {key}\nrank: {i}\n" for i, key in enumerate(keys)}
        for key, (docid, source) in zip(keys, sources.items(), strict=True):
            self.route("write", key, docid, source)
        control = self.raw()
        self.assertEqual(struct.unpack_from(">I", control, 8)[0], 0)
        state = control[48:]

        def blob(value):
            return struct.pack(">Q", len(value)) + value

        def scan(snapshot=b"", after=b"", credential="Bearer reader"):
            payload = (
                b"YSN1"
                + blob(state)
                + blob(b"alpha")
                + struct.pack(">QQQ", 3, 0, 0x7FFFFFFFFFFFFFFF)
                + blob(b"left")
                + blob(b"alpha")
                + blob(b"")
                + blob(after)
                + blob(snapshot)
                + blob(b"")
                + blob(b"")
                + blob(b"")
                + struct.pack(">QQQQ", 0, 0, 1, 1024 * 1024)
            )
            reply = self.raw(payload=payload, kind=3, destination=1, credential=credential)
            self.assertGreaterEqual(len(reply), 48)
            return struct.unpack_from(">I", reply, 8)[0], reply[48:]

        def page(payload):
            stream = io.BytesIO(payload)

            def number():
                return struct.unpack(">Q", stream.read(8))[0]

            def value():
                return stream.read(number())

            snapshot = value()
            count, end = number(), number()
            rows = [(value().decode(), value().decode()) for _ in range(count)]
            self.assertEqual(stream.read(), b"")
            return snapshot, end, rows

        status, first = scan()
        self.assertEqual(status, 0)
        snapshot, end, rows = page(first)
        self.assertEqual((bool(snapshot), end, rows), (True, 0, [next(iter(sources.items()))]))
        # A later commit must not replace the captured immutable generation.
        self.route(
            "write", keys[1], "doc1", "tenant: %d\nrank: 999\n" % keys[1], mutation_id="later"
        )
        self.send({"action": "unavailable", "node": 1, "value": True})
        self.addCleanup(self.send, {"action": "unavailable", "node": 1, "value": False})
        before = self.send({"action": "stats"})["reads"][1]
        for held in (snapshot, b"f" * 64):
            with self.subTest(held=held == snapshot):
                status, payload = scan(held, b"doc0")
                self.assertEqual(status, 12, "continuation served without a fresh proof")
                self.assertEqual(payload, b"")
        self.assertEqual(self.send({"action": "stats"})["reads"][1], before + 2)
        self.send({"action": "unavailable", "node": 1, "value": False})
        # A valid leader without this caller's capture must still report STALE.
        self.assertEqual(scan(b"f" * 64, b"doc0")[0], 6)
        before = self.send({"action": "stats"})["reads"][1]
        self.assertEqual(scan(snapshot, b"doc0", credential="Bearer unknown")[0], 11)
        self.assertEqual(self.send({"action": "stats"})["reads"][1], before)
        status, second = scan(snapshot, b"doc0")
        self.assertEqual(status, 0)
        self.assertEqual(page(second), (snapshot, 0, [("doc1", sources["doc1"])]))
        status, third = scan(snapshot, b"doc1")
        self.assertEqual(status, 0)
        self.assertEqual(page(third), (snapshot, 1, [("doc2", sources["doc2"])]))

    def test_original_caller_grants_precede_storage_and_retry_receipts(self):
        self.install()
        source = "# exact YAML\r\ntenant: 1\r\ncount: 7 # keep\r\n"
        original = self.route("write", source=source)
        updated = "tenant: 1\ncount: 8\n"
        self.route("write", source=updated, mutation_id="new-version")
        self.stop()
        self.start()
        self.assertEqual(self.route("write", source=source), original)
        self.assertEqual(self.route("read")["rows"][0]["source"], updated)
        before = self.send({"action": "stats"})
        self.route(
            "write",
            source="# exact YAML\r\ntenant: 1\r\ncount: 7 # keep\r\n",
            credential="Bearer reader",
            expected=403,
        )
        self.assertEqual(self.send({"action": "stats"})["writes"], before["writes"])
        reply = self.raw(credential="Bearer unknown")
        self.assertGreaterEqual(len(reply), 48)
        self.assertNotEqual(struct.unpack_from(">I", reply, 8)[0], 0)
        self.assertEqual(self.send({"action": "stats"})["reads"], before["reads"])
        reply = self.raw(payload=b"private")
        self.assertNotEqual(struct.unpack_from(">I", reply, 8)[0], 0)
        self.assertEqual(self.send({"action": "stats"})["reads"], before["reads"])

    def test_mtls_and_separate_alpn_reject_before_storage(self):
        self.install()
        before = self.send({"action": "stats"})
        cases = (
            {"identity": None},
            {"identity": "foreign-node"},
            {"identity": "beta"},
            {"identity": "stranger"},
            {"protocols": ("yamora-raft/1",)},
            {"protocols": ("yamora-binary/1",)},
            {"protocols": ()},
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(self.raw(**case), b"")
        self.assertEqual(self.send({"action": "stats"})["reads"], before["reads"])
        self.assertEqual(struct.unpack_from(">I", self.raw(), 8)[0], 0)

    def test_private_numeric_operator_registry(self):
        self.stop()
        config = self.configs[0]
        original = config.read_text()

        def check(value, expected=4):
            config.write_text(json.dumps(value))
            result = subprocess.run(
                [str(self.binary), "--check-config", str(config)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, expected, result.stderr)

        check(json.loads(original), expected=0)
        for address in ("localhost", "8.8.8.8", "169.254.1.1", "0.0.0.0", "::ffff:127.0.0.1"):
            with self.subTest(address=address):
                value = json.loads(original)
                value["peers"][1]["address"] = address
                check(value)
        value = json.loads(original)
        value["peers"][1]["name"] = value["peers"][0]["name"]
        check(value)
        value = json.loads(original)
        value["control_group"] = "unregistered"
        check(value)
        config.chmod(0o644)
        check(json.loads(original))
        config.chmod(0o600)

    def test_native_route_exact_sources_and_service_restart(self):
        self.install()
        sources = {
            f"doc{i:03}": f"# exact {i}\r\ntenant: {i}\r\nrank: {300 - i} # keep\r\n"
            for i in range(300)
        }
        for i, (docid, source) in enumerate(sources.items()):
            self.route("write", i, docid, source)
        query = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": 1,
            "sort": "rank",
            "offset": 19,
            "limit": 157,
            "max_rows": 400,
        }
        result = self.request("/v1/sharding/gather", query)
        self.assertEqual(result["matched"], 300)
        self.assertEqual(result["shards"], 2)
        expected = list(reversed(list(sources.items())))[19:176]
        self.assertEqual([(row["id"], row["source"]) for row in result["rows"]], expected)
        self.stop()
        self.start()
        self.assertEqual(self.request("/v1/sharding/gather", query), result)
        self.assertEqual(self.route("read", 0, "doc000")["rows"][0]["source"], sources["doc000"])
        self.route("read", 999, "doc000", expected=400)

    def test_migration_restart_every_phase_single_ownership_and_stale_epoch(self):
        self.install()
        for i in range(300):
            self.route("write", i, f"doc{i}", f"tenant: {i}\ncount: {i}\n")
        self.request(
            "/v1/sharding/migrate",
            {"collection": "docs", "shard": "left", "target": "beta", "mutation_id": "b" * 32},
        )
        self.stop()
        self.start()
        for _ in range(20):
            state = self.state()
            if state["migration"]["phase"] == 0:
                break
            query = {
                "collection": "docs",
                "placement_id": "a" * 32,
                "epoch": state["placement"]["epoch"],
                "limit": 300,
            }
            if state["migration"]["phase"] == 4:
                self.request("/v1/sharding/gather", query, expected=503)
            else:
                gathered = self.request("/v1/sharding/gather", query)
                self.assertEqual(gathered["matched"], 300)
                self.assertEqual(len(gathered["rows"]), 300)
            with self.subTest(migration=state["migration"]):
                self.request("/v1/sharding/step", {"collection": "docs"})
            self.stop()
            self.start()
        else:
            self.fail("migration did not finish")
        self.assertEqual(state["placement"]["epoch"], 2)
        self.assertTrue(all(r["group"] == "beta" for r in state["placement"]["ranges"]))
        self.route("read", 0, "doc0", expected=409)
        for i in range(300):
            self.assertEqual(
                self.route("read", i, f"doc{i}", epoch=2)["rows"][0]["source"],
                f"tenant: {i}\ncount: {i}\n",
            )
        result = self.request(
            "/v1/sharding/aggregate",
            {
                "collection": "docs",
                "placement_id": "a" * 32,
                "epoch": 2,
                "pipeline": [{"$group": {"_id": None, "total": {"$sum": "$count"}}}],
            },
        )
        self.assertEqual(result, [{"_id": None, "total": 44850}])

    @staticmethod
    def placement(collection, placement_id, field, shards, key_version=1, version=2):
        return {
            "version": version,
            "key_version": key_version,
            "algorithm": "sha256-64be-v1",
            "placement_id": placement_id,
            "collection": collection,
            "epoch": 1,
            "field": field,
            "ranges": [
                {
                    "first": "0000000000000000",
                    "last": "7fffffffffffffff",
                    "shard": shards[0],
                    "group": "alpha",
                },
                {
                    "first": "8000000000000000",
                    "last": "ffffffffffffffff",
                    "shard": shards[1],
                    "group": "beta",
                },
            ],
        }

    @staticmethod
    def key_bytes(value):
        """Independent canonical key encoder (sharding.md versions 1 and 2)."""

        def component(item):
            if isinstance(item, bool):
                return b"\x01\x00\x01" + bytes([item])
            if isinstance(item, int):
                return b"\x02\x00\x08" + item.to_bytes(8, "big", signed=True)
            data = item.encode()
            return b"\x03" + len(data).to_bytes(2, "big") + data

        if isinstance(value, list):
            return b"YSK\x02" + bytes([len(value)]) + b"".join(map(component, value))
        return b"YSK\x01" + component(value)

    def keyed(self, collection, placement_id, operation, key, docid, source=None, **kwargs):
        body = {
            "collection": collection,
            "placement_id": placement_id,
            "epoch": kwargs.pop("epoch", 1),
            "operation": operation,
            "key": key,
            "id": docid,
            "mutation_id": kwargs.pop("mutation_id", f"{collection}-{docid}"),
        }
        if source is not None:
            body["source"] = source
        return self.request("/v1/sharding/route", body, **kwargs)

    def test_compound_keys_and_cross_shard_lookup_bounds_and_authorization(self):
        people = self.placement("people", "c" * 32, "user", ("p-left", "p-right"))
        orders = self.placement(
            "orders", "d" * 32, ["org", "order"], ("o-left", "o-right"), key_version=2
        )
        self.request("/v1/sharding/install", people)
        self.request("/v1/sharding/install", orders)
        # A second collection cannot reuse a shard name of the namespace.
        clash = self.placement("docs", "e" * 32, "tenant", ("p-left", "d-right"))
        self.assertEqual(
            self.request("/v1/sharding/install", clash, expected=409), {"error": "conflict"}
        )
        state = self.request("/v1/sharding?collection=orders", method="GET")["placement"]
        self.assertEqual(
            (state["version"], state["key_version"], state["field"]), (2, 2, ["org", "order"])
        )
        for i in range(6):
            source = f"user: u-{i}\nlogin: u-{i}\nname: N{i}\n"
            self.keyed("people", "c" * 32, "write", f"u-{i}", f"u-{i}", source)
        order_sources = {}
        for i in range(8):
            org = "acme" if i % 2 == 0 else "zeta"
            order_sources[i] = f"# order {i}\norg: {org}\norder: {i}\nuser: u-{i % 3}\n"
            self.keyed("orders", "d" * 32, "write", [org, i], f"o-{i}", order_sources[i])
        self.assertEqual(
            self.keyed("orders", "d" * 32, "read", ["acme", 4], "o-4")["rows"][0]["source"],
            order_sources[4],
        )
        for key, error in (
            ("acme", "invalid_key"),
            (["acme"], "invalid_key"),
            (["acme", 4, 1], "invalid_key"),
            (["acme", None], "unsupported_key"),
            (["acme", 1.5], "unsupported_key"),
            ([None, 4], "unsupported_key"),
        ):
            with self.subTest(key=key):
                reply = self.keyed("orders", "d" * 32, "read", key, "o-4", expected=400)
                self.assertEqual(reply, {"error": error})
        # Every component is immutable, including one that keeps the same shard.
        changed = order_sources[4].replace("order: 4", "order: 40")
        self.keyed(
            "orders", "d" * 32, "write", ["acme", 4], "o-4", changed, mutation_id="m", expected=400
        )

        def aggregate(pipeline, credential="Bearer writer", expected=200, **bounds):
            body = {
                "collection": "orders",
                "placement_id": "d" * 32,
                "epoch": 1,
                "pipeline": pipeline,
                "explain": True,
                **bounds,
            }
            return self.request(
                "/v1/sharding/aggregate", body, credential=credential, expected=expected
            )

        def lookup(foreign_field, local_field="user"):
            return {
                "$lookup": {
                    "from": "people",
                    "localField": local_field,
                    "foreignField": foreign_field,
                    "as": "who",
                }
            }

        sort = {"$sort": {"order": 1}}

        def joined(reply, name="who", field="name"):
            return [
                (row["order"], [match[field] for match in row[name]]) for row in reply["results"]
            ]

        expected = [(i, [f"N{i % 3}"]) for i in range(0, 8, 2)]
        # The acme orders reference u-0..u-2 only; target the shards owning them.
        owners = {self.shard_of(f"u-{i}") for i in range(3)}
        targeted = aggregate([{"$match": {"org": "acme"}}, lookup("user"), sort])
        self.assertEqual(joined(targeted), expected)
        relation = targeted["lookups"][0]
        self.assertEqual(
            (relation["from"], relation["mode"], relation["shards"], relation["ranges"]),
            ("people", "targeted", len(owners), 2),
        )
        self.assertIs(targeted["global_snapshot"], False)
        # A foreign field that is not the shard key scatters; same result.
        scattered = aggregate([{"$match": {"org": "acme"}}, lookup("login"), sort])
        self.assertEqual(joined(scattered), expected)
        self.assertEqual(
            (scattered["lookups"][0]["mode"], scattered["lookups"][0]["shards"]), ("scatter", 2)
        )
        # A self lookup reuses the input's own shard views.
        same = {
            "$lookup": {"from": "orders", "localField": "org", "foreignField": "org", "as": "same"}
        }
        own = aggregate([same, sort])
        self.assertEqual(
            joined(own, "same", "order"),
            [(i, list(range(i % 2, 8, 2))) for i in range(8)],
        )
        self.assertEqual(own["lookups"][0]["mode"], "input")
        # Bounds fail the whole request without any partial result.
        for pipeline, bounds in (
            ([lookup("login")], {"max_foreign_rows": 1}),
            ([lookup("login")], {"max_foreign_bytes": 16}),
            ([lookup("login")], {"max_rows": 3}),
            ([same], {"max_matches": 3}),
        ):
            with self.subTest(bounds=bounds):
                reply = aggregate(pipeline, expected=413, **bounds)
                self.assertEqual(reply, {"error": "budget_exceeded"})
        # Foreign read authorization precedes any data-node call.
        before = self.send({"action": "stats"})
        denied = aggregate([lookup("user")], credential="Bearer orders-reader", expected=403)
        self.assertEqual(denied, {"error": "forbidden"})
        self.assertEqual(self.send({"action": "stats"})["reads"][1:], before["reads"][1:])
        count = {"$group": {"_id": None, "n": {"$sum": 1}}}
        reply = aggregate([count], credential="Bearer orders-reader")
        self.assertEqual(reply["results"], [{"_id": None, "n": 8}])

    def changes(self, after=None, credential="Bearer writer", expected=200, epoch=1, **extra):
        body = {"collection": "people", "placement_id": "c" * 32, "epoch": epoch, **extra}
        if after is not None:
            body["after"] = after
        return self.request("/v1/sharding/changes", body, credential=credential, expected=expected)

    def drain(self, token, epoch=1, limit=5):
        events = []
        for _ in range(200):
            page = self.changes(token, epoch=epoch, limit=limit)
            self.assertLessEqual(len(page["changes"]), limit)
            # Page order is range order (p-left, then p-right), then sequence.
            shards = [c["shard"] for c in page["changes"]]
            self.assertEqual(shards, sorted(shards))
            events += [
                (c["shard"], c["sequence"], c["operation"], c["id"], c.get("source"))
                for c in page["changes"]
            ]
            token = page["next_after"]
            if not page["has_more"]:
                return events, token
        self.fail("feed did not drain")

    def shard_of(self, user):
        digest = hashlib.sha256(self.key_bytes(user)).digest()
        return "p-right" if digest[0] >= 128 else "p-left"

    def test_change_feed_resume_restart_tokens_and_migration(self):
        self.install()
        self.assertEqual(
            self.request(
                "/v1/sharding/changes",
                {"collection": "docs", "placement_id": "a" * 32, "epoch": 1},
                expected=400,
            ),
            {"error": "unsupported_metadata"},
        )
        self.request(
            "/v1/sharding/install",
            self.placement("people", "c" * 32, "user", ("p-left", "p-right")),
        )
        origin = self.changes()
        self.assertEqual((origin["changes"], origin["has_more"]), ([], False))
        self.assertRegex(origin["next_after"], r"^ysf1\.[0-9a-f]+$")
        written = {}
        for i in range(12):
            source = f"user: u-{i}\nname: N{i}\n"
            self.keyed("people", "c" * 32, "write", f"u-{i}", f"u-{i}", source)
            written.setdefault(self.shard_of(f"u-{i}"), []).append(("write", f"u-{i}", source))
        self.assertEqual(sorted(written), ["p-left", "p-right"])
        self.keyed("people", "c" * 32, "delete", "u-2", "u-2", mutation_id="delete-u-2")
        written[self.shard_of("u-2")].append(("delete", "u-2", None))
        # A delete of an absent document and an exact retry log nothing.
        self.keyed("people", "c" * 32, "delete", "u-99", "u-99", mutation_id="delete-u-99")
        self.keyed("people", "c" * 32, "write", "u-0", "u-0", "user: u-0\nname: N0\n")

        def per_shard(events):
            """Each shard's events in order; sequences must run 1, 2, 3, ..."""
            grouped = {}
            for shard, sequence, operation, docid, source in events:
                rows = grouped.setdefault(shard, [])
                self.assertEqual(sequence, len(rows) + 1)
                rows.append((operation, docid, source))
            return grouped

        events, tail = self.drain(origin["next_after"])
        self.assertEqual(per_shard(events), written)
        self.assertEqual(self.changes()["next_after"], tail)
        # Same token, same changes and the same next token, also after restart.
        middle = self.changes(origin["next_after"], limit=4)
        self.stop()
        self.start()
        self.assertEqual(self.drain(origin["next_after"]), (events, tail))
        rest, rest_tail = self.drain(middle["next_after"])
        self.assertEqual(len(middle["changes"]) + len(rest), len(events))
        self.assertEqual(rest_tail, tail)
        # Admin only, and an unhonorable token fails loudly.
        self.changes(origin["next_after"], credential="Bearer reader", expected=403)
        body = tail[5:]
        flipped = body[:86] + ("1" if body[86] == "0" else "0") + body[87:]
        self.assertEqual(self.changes("ysf1." + flipped, expected=409), {"error": "conflict"})
        ahead = body[:70] + "00000000000fffff" + body[86:]
        self.assertEqual(self.changes("ysf1." + ahead, expected=409), {"error": "conflict"})
        for bad in ("ysf1.zz", "ysf2." + body, tail[:-2], 7):
            with self.subTest(token=bad):
                self.assertEqual(self.changes(bad, expected=400), {"error": "invalid_argument"})
        self.changes(tail, limit=0, expected=400)
        self.changes(tail, max_bytes=2 * 1024 * 1024, expected=400)
        self.changes(origin["next_after"], max_bytes=16, expected=413)
        # Migration of one shard with a restart around every step: the feed
        # stays exact from the same token, and numbering continues afterward.
        self.request(
            "/v1/sharding/migrate",
            {"collection": "people", "shard": "p-left", "target": "beta", "mutation_id": "f" * 32},
        )
        unavailable = 0
        for _ in range(20):
            self.stop()
            self.start()
            state = self.request("/v1/sharding?collection=people", method="GET")
            epoch = state["placement"]["epoch"]
            if state["migration"]["phase"] == 0:
                break
            if state["migration"]["phase"] == 4:
                self.changes(origin["next_after"], epoch=epoch, expected=503)
                unavailable += 1
            else:
                self.assertEqual(self.drain(origin["next_after"], epoch=epoch), (events, tail))
            self.request("/v1/sharding/step", {"collection": "people"})
        else:
            self.fail("migration did not finish")
        self.assertEqual((epoch, unavailable), (2, 1))
        # Same changes; the next token now records the epoch it was issued at.
        moved_events, moved_tail = self.drain(origin["next_after"], epoch=2)
        self.assertEqual(moved_events, events)
        self.assertEqual(moved_tail, tail[:39] + f"{2:016x}" + tail[55:])
        self.assertEqual(tail[39:55], f"{1:016x}")
        moved = "user: u-0\nname: moved\n"
        self.keyed(
            "people", "c" * 32, "write", "u-0", "u-0", moved, epoch=2, mutation_id="after-move"
        )
        after = self.changes(tail, epoch=2)
        shard = self.shard_of("u-0")
        self.assertEqual(
            [(c["shard"], c["sequence"], c["epoch"], c["source"]) for c in after["changes"]],
            [(shard, len(written[shard]) + 1, 2, moved)],
        )
        self.assertEqual(after["epoch"], 2)

    def test_destination_reauthorizes_routed_reads(self):
        self.install()
        self.route("write", source="tenant: 1\ncount: 1\n")
        self.send({"action": "deny", "node": 1, "value": True})
        self.send({"action": "deny", "node": 2, "value": True})
        before = self.send({"action": "stats"})
        self.route("read", expected=403)
        after = self.send({"action": "stats"})
        self.assertEqual(after["reads"][1:], before["reads"][1:])
        self.route("write", source="tenant: 1\ncount: 1\n", expected=403)
        self.assertEqual(self.send({"action": "stats"})["writes"], after["writes"])


if __name__ == "__main__":
    unittest.main()
