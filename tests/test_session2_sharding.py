"""Actual three-replica control/shard groups, router failover and distributed query conformance."""

import hashlib
import json
import socket
import subprocess
import time
import unittest

from yamora.tests import test_cluster_api as api

GROUPS = ("control", "alpha", "beta")


class Session2ShardingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api.ClusterApiTests.setUpClass.__func__(cls)
        for group in GROUPS:
            for node in range(1, 4):
                name = f"{group}{node}"
                extension = cls.directory / f"{name}.ext"
                extension.write_text(
                    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                    f"extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{name}.test\n"
                )
                for arguments in (
                    [
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
                    ],
                    [
                        "x509",
                        "-req",
                        "-in",
                        cls.directory / f"{name}.csr",
                        "-CA",
                        cls.directory / "trusted.pem",
                        "-CAkey",
                        cls.directory / "trusted.key",
                        "-set_serial",
                        str(100 + GROUPS.index(group) * 3 + node),
                        "-days",
                        "1",
                        "-extfile",
                        extension,
                        "-out",
                        cls.directory / f"{name}.pem",
                    ],
                ):
                    subprocess.run(
                        ["openssl", *map(str, arguments)],
                        capture_output=True,
                        check=True,
                        timeout=20,
                    )

    def setUp(self):
        self.groups = {}
        self.endpoints = []
        for group in GROUPS:
            cluster = api.ClusterApiTests()
            cluster.directory, cluster.certificates = self.directory, self.certificates
            cluster.setUp()
            self.addCleanup(cluster.doCleanups)
            self.groups[group] = cluster
            for i in range(3):
                cluster.peers[i]["name"] = f"{group}{i + 1}.test"
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                self.endpoints.append(
                    {
                        "group": group,
                        "name": f"{group}{i + 1}.test",
                        "address": "127.0.0.1",
                        "port": port,
                    }
                )
        for group, c in self.groups.items():
            files = []
            for i in range(3):
                name = f"{group}{i + 1}"
                tls = {
                    "cert_file": str(self.directory / f"{name}.pem"),
                    "key_file": str(self.directory / f"{name}.key"),
                    "ca_file": str(self.directory / "trusted.pem"),
                }
                spec = c.spec(i)
                spec["cluster"] = f"{GROUPS.index(group) + 1:032x}"
                spec["peer_tls"] = tls
                c.save(i, spec)
                config = c.root / f"shard{i}.json"
                endpoint = self.endpoints[GROUPS.index(group) * 3 + i]
                config.write_text(
                    json.dumps(
                        {
                            "version": 1,
                            "local_name": name + ".test",
                            "local_group": group,
                            "control_group": "control",
                            "listen": {"address": "127.0.0.1", "port": endpoint["port"]},
                            "peer_tls": tls,
                            "peers": self.endpoints,
                            "request_timeout_ms": 3000,
                        }
                    )
                )
                config.chmod(0o600)
                files.append(config)
            original = c.arguments

            def arguments(i, original=original, files=files):
                return original(i) + ["--shard-config-file", str(files[i])]

            c.arguments = arguments
        self.router = ("control", 0)

    def request(self, path, body=None, *, method="POST", expected=200, token="w" * 32):
        group, node = self.router
        reply = self.groups[group].request(node, method, path, body, token=token)
        self.assertEqual(reply[0], expected, reply[2])
        return json.loads(reply[2])

    def route(self, operation, key, *, source=None, epoch=1, mutation=None, expected=200):
        body = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": epoch,
            "operation": operation,
            "key": key,
            "id": f"doc{key:03}",
            "mutation_id": mutation or f"write-{key}",
        }
        if source is not None:
            body["source"] = source
        return self.request("/v1/sharding/route", body, expected=expected)

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

    def test_native_groups_route_gather_aggregate_and_migrate_through_leader_loss(self):
        leaders = {group: c.launch() for group, c in self.groups.items()}
        self.router = ("control", leaders["control"])
        self.install()
        sources = {
            i: f"# exact {i}\r\ntenant: {i}\r\nrank: {i % 5}\r\ncount: {i}\r\n" for i in range(30)
        }
        for key, source in sources.items():
            self.route("write", key, source=source)
        query = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": 1,
            "sort": "rank",
            "offset": 7,
            "limit": 12,
            "max_rows": 100,
        }
        result = self.request("/v1/sharding/gather", query)
        self.assertEqual((result["matched"], result["shards"]), (30, 2))
        expected = sorted(sources, key=lambda i: (i % 5, f"doc{i:03}"))[7:19]
        self.assertEqual(
            [(r["id"], r["source"]) for r in result["rows"]],
            [(f"doc{i:03}", sources[i]) for i in expected],
        )
        aggregation = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": 1,
            "pipeline": [{"$group": {"_id": None, "total": {"$sum": "$count"}}}],
        }
        reduced = self.request("/v1/sharding/aggregate", aggregation)
        self.assertEqual([r["total"] for r in reduced], [435])
        self.request("/v1/sharding/gather", query, expected=403, token="s" * 32)
        for group in GROUPS:
            self.groups[group].stop(leaders[group], crash=True)
            self.groups[group].wait(self.groups[group].leader)
        self.router = ("alpha", self.groups["alpha"].leader())
        self.assertEqual(self.request("/v1/sharding/gather", query), result)
        self.route("write", 0, source=sources[0])
        self.route("write", 0, source=sources[0] + "# changed\n", expected=409)
        self.request(
            "/v1/sharding/migrate",
            {"collection": "docs", "shard": "left", "target": "beta", "mutation_id": "b" * 32},
        )
        for _ in range(30):
            state = self.request("/v1/sharding?collection=docs", method="GET")
            if not state["migration"]["phase"]:
                break
            self.request("/v1/sharding/step", {"collection": "docs"})
        else:
            self.fail("bounded migration did not complete")
        self.assertEqual(state["placement"]["epoch"], 2)
        self.route("read", 0, expected=409)
        for key, source in sources.items():
            self.assertEqual(self.route("read", key, epoch=2)["rows"][0]["source"], source)
        query["epoch"] = 2
        durations = []
        for _ in range(12):
            start = time.monotonic()
            self.assertEqual(self.request("/v1/sharding/gather", query), result)
            durations.append((time.monotonic() - start) * 1000)
        print(
            "SESSION2_SHARD_QUERY "
            + json.dumps(
                {
                    "hosts": 1,
                    "groups": 3,
                    "voters": 9,
                    "rows": 30,
                    "calls": 12,
                    "milliseconds": durations,
                }
            ),
            flush=True,
        )

    def changes(self, after=None, *, epoch=1, expected=200, token="w" * 32):
        body = {"collection": "people", "placement_id": "c" * 32, "epoch": epoch, "limit": 7}
        if after is not None:
            body["after"] = after
        return self.request("/v1/sharding/changes", body, expected=expected, token=token)

    def drain(self, after, epoch=1):
        events = []
        for _ in range(100):
            page = self.changes(after, epoch=epoch)
            events += [
                (c["shard"], c["sequence"], c["operation"], c["id"]) for c in page["changes"]
            ]
            after = page["next_after"]
            if not page["has_more"]:
                return events, after
        self.fail("change feed did not drain")

    def person(self, i, *, epoch=1, expected=200):
        body = {
            "collection": "people",
            "placement_id": "c" * 32,
            "epoch": epoch,
            "operation": "write",
            "key": f"u-{i}",
            "id": f"u-{i}",
            "mutation_id": f"person-{i}-{epoch}",
            "source": f"user: u-{i}\nepoch: {epoch}\n",
        }
        return self.request("/v1/sharding/route", body, expected=expected)

    def test_change_feed_survives_shard_leader_loss_and_partition_migration(self):
        leaders = {group: c.launch() for group, c in self.groups.items()}
        self.router = ("control", leaders["control"])
        self.request(
            "/v1/sharding/install",
            {
                "version": 2,
                "key_version": 1,
                "algorithm": "sha256-64be-v1",
                "placement_id": "c" * 32,
                "collection": "people",
                "epoch": 1,
                "field": "user",
                "ranges": [
                    {
                        "first": "0000000000000000",
                        "last": "7fffffffffffffff",
                        "shard": "p-left",
                        "group": "alpha",
                    },
                    {
                        "first": "8000000000000000",
                        "last": "ffffffffffffffff",
                        "shard": "p-right",
                        "group": "beta",
                    },
                ],
            },
        )
        origin = self.changes()["next_after"]
        self.changes(origin, expected=403, token="r" * 32)
        for i in range(20):
            self.person(i)
        events, tail = self.drain(origin)
        self.assertEqual(sorted(e[3] for e in events), sorted(f"u-{i}" for i in range(20)))
        for shard in ("p-left", "p-right"):
            numbers = [e[1] for e in events if e[0] == shard]
            self.assertEqual(numbers, list(range(1, len(numbers) + 1)))
            self.assertTrue(numbers, shard)
        # Crash every group leader: the committed logs move with the data.
        for group in GROUPS:
            self.groups[group].stop(leaders[group], crash=True)
            self.groups[group].wait(self.groups[group].leader)
        self.router = ("alpha", self.groups["alpha"].leader())
        self.assertEqual(self.drain(origin), (events, tail))
        for i in range(20, 26):
            self.person(i)
        later, tail = self.drain(tail)
        self.assertEqual(sorted(e[3] for e in later), sorted(f"u-{i}" for i in range(20, 26)))
        # Page boundaries decide the interleaving of shards, so compare one
        # complete drain from the origin with the two chained drains.
        whole, whole_tail = self.drain(origin)
        self.assertEqual((sorted(whole), whole_tail), (sorted(events + later), tail))
        events = whole
        for shard in ("p-left", "p-right"):
            numbers = [e[1] for e in events if e[0] == shard]
            self.assertEqual(numbers, list(range(1, len(numbers) + 1)))
        # Migrate p-left; the same token stays exact through every phase.
        self.request(
            "/v1/sharding/migrate",
            {"collection": "people", "shard": "p-left", "target": "beta", "mutation_id": "f" * 32},
        )
        unavailable = 0
        for _ in range(30):
            state = self.request("/v1/sharding?collection=people", method="GET")
            epoch = state["placement"]["epoch"]
            if not state["migration"]["phase"]:
                break
            if state["migration"]["phase"] == 4:
                # Published but not yet activated: no partial log is served.
                self.changes(origin, epoch=epoch, expected=503)
                unavailable += 1
            else:
                self.assertEqual(self.drain(origin, epoch=epoch)[0], events)
            self.request("/v1/sharding/step", {"collection": "people"})
        else:
            self.fail("bounded migration did not complete")
        self.assertEqual((epoch, unavailable), (2, 1))
        self.assertEqual(self.drain(origin, epoch=2)[0], events)
        self.person(0, epoch=2)
        after, _ = self.drain(tail, epoch=2)
        left = sum(e[0] == "p-left" for e in events)
        right = sum(e[0] == "p-right" for e in events)
        moved = {"p-left": left + 1, "p-right": right + 1}
        self.assertEqual(len(after), 1)
        self.assertEqual(after[0][1], moved[after[0][0]])
        self.assertEqual(after[0][3], "u-0")

    def test_multipage_scan_reaches_nonfirst_shard_leaders(self):
        control = self.groups["control"]
        self.router = ("control", control.launch())
        for group in ("alpha", "beta"):
            cluster = self.groups[group]
            # Elect from the final two registry entries before the first peer joins.
            for node in (1, 2):
                cluster.start(node)
            leader = cluster.wait(cluster.leader)
            self.assertIn(leader, (1, 2))
            cluster.start(0)
            cluster.wait(lambda cluster=cluster: cluster.status(0)["role"] == "follower")
            self.assertEqual(cluster.leader(), leader)
        self.install()
        sources = {
            i: f"# multipage {i}\r\ntenant: {i}\r\nrank: {i % 7}\r\ncount: {i}\r\n"
            for i in range(288)
        }
        counts = {"alpha": 0, "beta": 0}
        for key, source in sources.items():
            self.route("write", key, source=source)
            encoded = b"YSK\x01\x02\x00\x08" + key.to_bytes(8, "big")
            group = "alpha" if hashlib.sha256(encoded).digest()[0] < 128 else "beta"
            counts[group] += 1
        self.assertGreater(min(counts.values()), 128)
        query = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": 1,
            "sort": "rank",
            "limit": 288,
            "max_rows": 400,
        }
        expected = sorted(sources, key=lambda i: (i % 7, f"doc{i:03}"))
        for offset, limit in ((0, 288), (19, 157)):
            with self.subTest(offset=offset, limit=limit):
                result = self.request(
                    "/v1/sharding/gather", dict(query, offset=offset, limit=limit)
                )
                self.assertEqual((result["matched"], result["shards"]), (288, 2))
                self.assertEqual(
                    [(row["id"], row["source"]) for row in result["rows"]],
                    [(f"doc{i:03}", sources[i]) for i in expected[offset : offset + limit]],
                )
